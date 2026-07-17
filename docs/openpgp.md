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

`C_Login` selects the applet, establishes the configured secure channel if
needed, and verifies the user PIN. When the applet publishes an OpenPGP KDF
Data Object (`F9`), the client derives the value sent to `VERIFY` using the
advertised iterated salted S2K parameters. SHA-256 and SHA-512 KDF hashes are
supported. The clear PIN is not sent to the applet when this KDF is active.

Operations that require applet authentication re-verify the cached derived
PIN as required by the OpenPGP PIN policy. `C_Logout` clears the applet's
authentication state, cached PIN, and applet-scoped secure-channel state.

## APDU capabilities

The OpenPGP protocol layer supports short and extended APDUs. Large signing,
RSA deciphering, and random-data requests use extended encoding where needed;
the shared PC/SC transport also supports command and response chaining for
protected applet traffic.

Internal helpers exist for changing the user PIN and writing OpenPGP data
objects, but those helpers are not currently wired to exported PKCS #11
`C_SetPIN` or general data-object management functions. Key generation,
private-key import, attestation, and UIF administration are likewise outside
the current PKCS #11 OpenPGP surface.
