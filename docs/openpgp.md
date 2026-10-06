# YubiKey OpenPGP client

The slot uses the [selective composition layer](architecture.md#shared-software-session-objects-and-mechanism-discovery).
It adds public-side operations, composite hashing, YubiHSM-auth ECDH support,
and consumers for secrets returned by ECDH. It does not expose unrelated
software algorithms, private-key generation, or secret-key generation. Device
operations and token objects retain the native limits described below. Native
mechanisms and composed hashed-signature or prefixed-ECDH modes carry `CKF_HW`
when the long-term private-key operation remains in the applet. Operations on a
materialized host secret do not. A merged mechanism retains `CKF_HW` when at
least one operation has a hardware-held secret path.

The OpenPGP client exposes the YubiKey OpenPGP smart-card applet as a PKCS #11
slot over native CCID transport. Common CCID discovery
and slot behavior is documented in [`ccid.md`](ccid.md). To limit discovery to
OpenPGP, configure it with:

```text
PKCS11RS_CCID_APPLICATIONS=openpgp
```

Native desktop builds use PC/SC, and native iOS builds use CryptoTokenKit.
SCP03 or SCP11 configuration is documented in [`scp03.md`](scp03.md) and
[`scp11.md`](scp11.md).

## Virtual devices

Configured embedded readers with the `openpgp` applet use the same
`virtual-yubikey-core` implementation as the USB gadget. The core supports
persistent RSA/ECC/Ed25519/X25519 keys, certificates, PIN/recovery policy,
signing, decipher, and applet reset. Every form uses the shared per-applet
storage runtime and the same `openpgp-<serial>.cbor` record.
Connection authorization is not persisted. See the
[virtual OpenPGP model](https://github.com/qpernil/virtual-yubikey/blob/main/docs/openpgp.md) for advertised
algorithms and optional-feature boundaries. Client restrictions against
potentially key-destructive operations apply to both virtual and physical cards.

### Physical RSA qualification

`tools/openpgp-rsa-matrix.py` compares all 13 RSA sizes with an explicitly
selected physical test YubiKey. It sends algorithm attributes directly to the
card so unsupported sizes are rejected by the firmware rather than an SDK
allowlist. It generates a signature key, imports independent host-generated
keys into the decipher and authentication slots, and verifies signatures and
decryption with `cryptography`. Rejections include their operation stage and
APDU status in the JSON report; rejection of an advertised size fails the test.
The final public keys are checked after applet reselection and their fingerprints
are saved in the report. After unplugging and reinserting the test key,
`--check-retention --serial TEST_SERIAL --report rsa-qualification.json`
checks those fingerprints, rejects private operations before fresh PIN
verification, and verifies signing, decryption and authentication afterwards.
This mode does not replace keys or require admin authentication. For older
reports without fingerprints, `--capture-retention-baseline` records the final
keys before the unplug/reinsert step and refuses to overwrite an existing baseline.

This test irreversibly replaces all three ordinary OpenPGP keys. Use a spare
device, disconnect other YubiKeys, and provide fresh PINs when prompted. The
harness refuses serial `10462967`, firmware `5.2.4`, mismatched serials, multiple
connected keys, and existing report files before opening OpenPGP. It verifies
the selected CCID endpoint's serial through Management before selecting OpenPGP.
It does not reset the applet or change PINs, touch policies, or certificates.

Run with a Python environment containing `yubikey-manager` and `cryptography`:

```sh
python tools/openpgp-rsa-matrix.py --serial TEST_SERIAL \
  --replace-openpgp-keys --report rsa-qualification.json
```

`--halve-rsa-step` tests 2048 plus increments of 256, 128, 64, 32, 16, 8, 4, 2
and 1 bit. Attribute readback and actual public-key size distinguish exact support
from rounding; only successful generation/import and crypto operations count as
qualified. The report records the smallest qualified increment separately for
each slot. These probes establish behavior near 2048, not acceptance of every
size throughout the RSA range. The test finishes with fresh 2048-bit keys. On the qualified
YubiKey 5 NFC (firmware 5.7.4), the 256-bit increment passed in all three slots;
all eight smaller increments returned `6A80` at the attribute write.

`--pinentry /path/to/pinentry-mac` uses PIN dialogs instead of terminal prompts.
`--factory-user-pin` explicitly uses the factory user PIN `123456` for the
duration of this test. `--factory-admin-pin` opts into one verification with
the factory admin PIN `12345678`; otherwise admin authentication requires fresh
PIN entry. These flags apply only to the qualification harness.
No submitted PIN is cached for later verification. A failed authentication
stops the test without automatic retries. Reports contain only device identity,
advertised sizes and test outcomes.
The device-selection guards have hardware-free tests:
`python -m unittest discover -s tools -p 'test_openpgp_rsa_matrix.py'`.

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

Readable cardholder, private-use, fingerprint, CA-fingerprint, and key
generation-time data objects are exposed as read-only `CKO_DATA` objects.
Their OpenPGP tag is returned in `CKA_OBJECT_ID`, and `CKA_VALUE` is fetched
from the applet only when first requested.

Key Information (`DE`) distinguishes empty, device-generated, and imported
keys. Device-generated keys report `CKA_LOCAL=true` and their corresponding
PKCS #11 key-pair generation mechanism. Imported keys report
`CKA_LOCAL=false`; when status is unavailable, the client uses the same
conservative non-local value.

The applet version and serial number are reported in the slot and token
information. The token-wide minimum is the smaller of the user and admin
password minima, and the maximum is the larger of their applet-reported
maxima. Each login and password-change path still enforces the limits for its
specific password reference.

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
- RSA, ECDSA, ECDH, Ed25519, and X25519 key-pair generation through the
  corresponding PKCS #11 key-pair generation mechanisms.
- RSA and elliptic-curve private-key import through `C_CreateObject`.

RSA keys from 1024 through 4096 bits in 256-bit steps are recognized.
Virtual devices advertise 2048, 3072 and 4096 through Algorithm Information (`FA`)
and accept 2048–4096 in 256-bit steps through algorithm attributes, matching
physical YubiKey 5 NFC firmware 5.7.4 qualification. The client also recognizes
1024–1792 in 256-bit steps for other card implementations; physical devices retain
their applet-specific size limits. Supported elliptic-curve
metadata includes P-256, P-384, P-521, Brainpool P-256/P-384/P-512,
secp256k1, Ed25519, and X25519. Actual availability depends on the key present
in the card and the firmware's OpenPGP implementation.

`CKA_ID` selects the OpenPGP key reference: `01` for signature, `02` for
decipher, and `03` for authentication. Generation and import require token
objects and matching IDs and algorithms. The operation is accepted only when
Key Information (`DE`) reports the selected reference as empty.

OpenPGP UIF is exposed on private keys through
`CKA_YUBICO_TOUCH_POLICY`. Values are `1` (off), `2` (on), `3` (cached), `4`
(fixed), and `5` (cached-fixed). The attribute can be supplied during
generation or import and changed later with `C_SetAttributeValue` in a
read/write session. Fixed policies cannot be weakened without replacing the
key; that restriction is enforced by the applet.

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

When a prompt provider is configured, the token reports
`CKF_PROTECTED_AUTHENTICATION_PATH`; a null PIN and zero length prompts for PW1
or PW3 according to the requested role.

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
Generation and import use guarded command paths that re-read Key Information
immediately before the mutating APDU and proceed only for an empty reference.
The general OpenPGP APDU path continues to reject potentially key-destructive
commands before transport, including application termination and activation,
retry count changes, unguarded key generation or import, and writes to key
algorithm attributes.

Discovery and public-key retrieval remain read-only. Certificate, UIF, and
general data-object helpers cannot bypass the key-preservation checks, while
ordinary PIN changes and PIN unblocking remain available because they do not
replace key material.
