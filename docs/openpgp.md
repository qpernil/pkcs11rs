# YubiKey OpenPGP client

The OpenPGP client exposes the YubiKey OpenPGP smart-card applet as a PKCS #11
slot over PC/SC. Common CCID discovery and slot behavior is documented in
[`ccid.md`](ccid.md). To limit discovery to OpenPGP, configure it with:

```text
PKCS11RS_CCID_APPLICATIONS=openpgp
```

The default transport is direct PC/SC. SCP03 or SCP11 configuration is
documented in [`scp03.md`](scp03.md) and [`scp11.md`](scp11.md).

## Discovery

Slot initialization selects the OpenPGP applet and reads its Application
Related Data (`6E`). The client discovers the signature, decipher, and
authentication key references:

| Reference | OpenPGP key use | PKCS #11 use |
| --- | --- | --- |
| `01` | Signature | Signing |
| `02` | Decryption or ECDH | RSA decryption or `CKM_ECDH1_DERIVE` |
| `03` | Authentication | Signing |

For each usable key, the slot exposes a token `CKO_PUBLIC_KEY` and
`CKO_PRIVATE_KEY` object. Private objects are sensitive, non-extractable, and
local to the token. Public key material is read from the applet, while an
available certificate is exposed as a `CKO_CERTIFICATE` object with its DER
value and standard X.509 attributes when they can be parsed.

On YubiKeys that advertise the optional attestation key reference (`81`), the
slot also exposes its public key, private-key identity, and attestation
certificate. Like the other private keys, the attestation private object uses
`CKA_PRIVATE=true` and is visible after login. It remains sensitive and
non-extractable, with all ordinary cryptographic capabilities disabled because
actual attestation uses the applet-specific command. Cards without this
extension continue to expose only the three standard key references.

Key Information (`DE`) distinguishes empty, device-generated, and imported
keys. Device-generated keys report `CKA_LOCAL=true` and their corresponding
PKCS #11 key-pair generation mechanism. Imported keys report
`CKA_LOCAL=false`; when status is unavailable, the client uses the same
conservative non-local value.

The applet version and serial number are reported in the slot and token
information. PIN minimum and maximum lengths come from the applet metadata.

## Supported operations

The current PKCS #11 surface includes:

- RSA signing with `CKM_RSA_PKCS`, `CKM_SHA256_RSA_PKCS`,
  `CKM_SHA384_RSA_PKCS`, and `CKM_SHA512_RSA_PKCS`.
- ECDSA signing with `CKM_ECDSA`, `CKM_ECDSA_SHA256`,
  `CKM_ECDSA_SHA384`, and `CKM_ECDSA_SHA512`.
- Ed25519 signing with `CKM_EDDSA`.
- RSA decryption with `CKM_RSA_X_509` and `CKM_RSA_PKCS`.
- ECDH key agreement with `CKM_ECDH1_DERIVE`, `CKD_NULL`, and no shared
  data. The decipher key reference is used for ECDH.
- Random data through `C_GenerateRandom`, using the applet's `GET CHALLENGE`
  command.

RSA keys from 1024 through 4096 bits are recognized. Supported elliptic-curve
metadata includes P-256, P-384, P-521, Brainpool P-256/P-384/P-512,
secp256k1, Ed25519, and X25519. Actual availability depends on the key present
in the card and the firmware's OpenPGP implementation.

The host performs the PKCS #1 v1.5 encoding and decoding required by the
corresponding PKCS #11 RSA mechanisms. ECDSA responses are converted from the
OpenPGP applet's DER form to PKCS #11's fixed-width `r || s` form.

## PIN handling

`C_Login` selects the applet and establishes the configured secure channel if
needed. `CKU_USER` verifies PW1, while `CKU_SO` verifies the OpenPGP
administrator password PW3. SO login requires a read/write session and cannot
coexist with read-only sessions. When the applet publishes an OpenPGP KDF Data
Object (`F9`), the client derives PW1 and PW3 using their advertised salts
before sending `VERIFY`. SHA-256 and SHA-512 KDF hashes are supported. The
clear PIN is not sent to the applet when this KDF is active.

No clear or derived PIN is cached. `CKU_CONTEXT_SPECIFIC` login supplies a PIN
for an operation that needs a fresh PW1 verification. `C_Logout` clears the
applet authentication state and applet-scoped secure-channel state.

In a read/write session, `C_SetPIN` changes PW3 while SO is logged in and PW1
otherwise, using `CHANGE REFERENCE DATA`. `C_InitPIN` resets PW1 under an
existing SO login using `RESET RETRY COUNTER`. When KDF is active, values are
derived for their respective password references before transmission. A
successful or attempted OpenPGP `C_SetPIN` clears the module's login state
because selecting the applet also resets its password-verification state.

## APDU capabilities

The OpenPGP protocol layer supports short and extended APDUs, ISO command and
response chaining, and the non-destructive commands needed for discovery,
authentication, cryptographic operations, certificate access, attestation,
and PIN management.

## Key preservation

The module never deletes or replaces OpenPGP keys. `C_DestroyObject` returns
`CKR_ACTION_PROHIBITED` for every OpenPGP object and leaves the object visible.
The OpenPGP APDU client also rejects potentially key-destructive commands
before transport, including application termination and activation, retry
count changes, key generation, private-key import, and writes to key algorithm
attributes. These commands return `CKR_ACTION_PROHIBITED` and no APDU is sent.

Discovery and public-key retrieval remain read-only. Certificate, UIF, and
general data-object helpers cannot bypass the key-preservation checks, while
ordinary PIN changes and PIN unblocking remain available because they do not
replace key material.
