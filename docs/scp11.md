# SCP11a, SCP11b, and SCP11c configuration

Set `PKCS11RS_CCID_SECURE_CHANNEL=scp11b` to establish an SCP11b secure
channel for the selected CCID applet over native CCID transport. See
[`ccid.md`](ccid.md) for the default applet list, allowlist, AID
overrides, and shared-slot behavior. YubiKey SCP11 support requires firmware
5.7.2 or later.

Set `PKCS11RS_CCID_SECURE_CHANNEL=scp11a` to use SCP11a instead. SCP11a adds
mutual authentication and requires the OCE credentials described below.

Set `PKCS11RS_CCID_SECURE_CHANNEL=scp11c` to use SCP11c. It uses the same OCE
credentials as SCP11a, with the SCP11c key referenced by KID `0x15`.

The Issuer SD is used separately for Secure Domain management.

For a proposed device-enforced channel requirement and per-key authorization
model, see [SCP requirements and applet key authorization](scp-applet-authorization-proposal.md).
Those policies require firmware support and are not implemented configuration.

SCP11b authenticates the card to the host. On a stock YubiKey with firmware
5.7.4 or later, the module validates the Security Domain certificate chain
against its embedded Yubico Attestation Root 1 and published Yubico
intermediates. The portable RFC 5280 path validator processes critical
certificate policies, verifies signatures and validity, and enforces CA and
path constraints. Presented certificates cannot add trust anchors. This supports the factory
SCP11b identity without additional trust configuration.

Custom-provisioned devices may override the factory trust anchor using exactly
one of:

- `PKCS11RS_SCP11_SD_PUBLIC_KEY`: the 65-byte uncompressed SEC1 public point,
  encoded as hexadecimal;
- `PKCS11RS_SCP11_SD_CA_CERTIFICATE`: path to one canonical DER X.509 CA
  certificate that authenticates the SD certificate chain.

`scp11.sd_intermediate_bundle` or `PKCS11RS_SCP11_SD_INTERMEDIATE_BUNDLE`
optionally supplies a canonical CBOR collection of card-side CA intermediates.
These complete the card's chain to the selected root; they do not add trust.
Self-issued roots and end-entity certificates are rejected in this bundle.
Factory trust includes the published intermediates even when this setting is
omitted. A public-key pin cannot be combined with a nonempty intermediate bundle.
The separate OCE intermediate bundle supplies the host chain sent to the card.

Create a card-intermediate bundle using the certificate-collection purpose:

```sh
pkcs11rs-tool certificate-bundle create \
  --purpose certificate-collection \
  --output /etc/pkcs11rs/card-intermediates.cbor \
  card-intermediate.pem
```

Configure the CA certificate and intermediates independently, for example:

```json
{
  "version": 1,
  "ccid": {"applications": ["issuer-sd"], "secure_channel": "scp11b"},
  "scp11": {
    "sd_ca_certificate": "/etc/pkcs11rs/card-root.der",
    "sd_intermediate_bundle": "/etc/pkcs11rs/card-intermediates.cbor"
  }
}
```

In factory or configured CA-certificate mode, the module obtains trust material
once per connected card and trust policy by temporarily selecting the Issuer
SD and reading the chain for the configured SCP11 KID/KVN. It validates the
chain against the selected CA, including validity periods and CA constraints,
and caches the validated leaf P-256 public key. The module then selects the
target applet and performs the actual SCP11 handshake there. Later channel
establishment reuses the validated public key without selecting the Issuer SD.
The cache is
discarded after reconnection or Security Domain mutation. The module never
implicitly trusts a certificate obtained from the card.

Trust-material acquisition occurs lazily during channel establishment at
login. Later handshakes use the connection-scoped validated-key cache.
If the selected card KID/KVN has no certificate bundle, login returns
`CKR_KEY_HANDLE_INVALID` and logs the requested SCP11 variant and key reference.
For example, an SCP11a login against a factory SCP11b-only card fails this way;
it does not fall back to SCP11b. Malformed or untrusted certificate bundles
remain certificate-validation failures.

Optional configuration:

- `PKCS11RS_SCP11_KEY_VERSION`: decimal or `0x` key version, default `1`;

The configured credential path for SCP11a and SCP11c additionally requires:

- `PKCS11RS_SCP11_OCE_PRIVATE_KEY`: path to a password-encrypted PKCS #8 DER
  P-256 private key, unlocked through `PKCS11RS_PINENTRY`;
- `PKCS11RS_SCP11_OCE_CERTIFICATE_BUNDLE`: path to a canonical CBOR certificate
  bundle ordered from leaf to issuer;
- `PKCS11RS_SCP11_OCE_KEY_VERSION`: OCE key version, default `0`;
- `PKCS11RS_SCP11_OCE_KEY_ID`: OCE key identifier, default `0`.

The leaf certificate public key must match the configured OCE private key, and
each certificate's signature must verify against the next issuer in the
configured chain.
Use the `scp11-oce` purpose of
[`pkcs11rs-tool`](pkcs11rs-tool.md) to import DER or PEM certificates, enforce
these constraints, match the encrypted key, and write the canonical CBOR
bundle.

```sh
pkcs11rs-tool certificate-bundle create \
  --purpose scp11-oce \
  --key /etc/pkcs11rs/oce-key.der \
  --output /etc/pkcs11rs/oce-chain.cbor \
  oce-leaf.der oce-issuers.pem
```

## Dynamic OCE credentials

`C_LoginUser` accepts a PKCS #11 URI selecting an already authorized provider's
token P-256 private key. `ccid.client_uri` or `PKCS11RS_CCID_CLIENT_URI` supplies
the same selector for `C_Login` and empty-username `C_LoginUser`; a nonempty
username overrides it. The target applet PIN remains the PIN argument.
The source must also contain exactly one token X.509 leaf certificate with the
private key's nonempty `CKA_ID`. The module verifies its public key against the
bound private key; it never reads the private scalar. Source authorization
is separate and must remain available for later handshakes.

A single leaf is sufficient when the card's provisioned OCE CA directly verifies
it. Otherwise supply public intermediates using `scp11.oce_intermediate_bundle`
or `PKCS11RS_SCP11_OCE_INTERMEDIATE_BUNDLE`. This is a canonical CBOR certificate
collection, loaded once from configuration. It supplies issuer certificates,
without supplying trust to either the host or card. The module constructs a
leaf-first chain using issuer names, key identifiers when available, and
verified signatures. Issuer validity and CA constraints are checked; ambiguous
paths fail. A self-issued root is omitted from the uploaded chain. A missing
intermediate does not trigger provider enumeration; the card rejects any chain
that cannot reach its provisioned trust.

The chain is sent issuer-first, with the leaf last, using PERFORM SECURITY
OPERATION before each handshake. The client retains its resolved public chain
for session recreation, but does not assume the card retains it. Temporary
OCE public-key storage authorizes the next handshake only; applet selection
also clears uploaded credentials in the virtual target. GlobalPlatform defines
an optional persistent OCE public-key mode for SCP11a, which can survive even
power loss. That option is not qualified for this client or the physical
YubiKey; see [GlobalPlatform SCP11, sections 4.1 and 7.5](https://globalplatform.org/wp-content/uploads/2023/08/GPC_2.3_F_SCP11_v1.3.0.13_PublicRvw.pdf).

```sh
pkcs11rs-tool certificate-bundle create \
  --purpose certificate-collection \
  --output /etc/pkcs11rs/oce-intermediates.cbor \
  oce-intermediate.pem
```

`scp11.oce_key_id` and `scp11.oce_key_version` select the OCE reference for
both credential paths. Dynamic mode uses the same card-trust configuration
as configured mode. Without a configured protocol, a private-key selector
chooses SCP11a. SCP11c requires `ccid.secure_channel=scp11c`; the URI still
selects the host credential, and cannot request SCP11c itself. See
[CCID login and recreation](ccid.md#login-selected-secure-channels) for lifetime
and qualification limits.

## Secure messaging and provider operations

The SCP11b transport uses NIST P-256 ephemeral key agreement and KID `0x13`.
The SCP11a and SCP11c transports upload the OCE certificate chain, use KID
`0x11` and `0x15` respectively, and combine ephemeral and static ECDH. All use
AES-128 session keys and the
mandatory `0x33` security level with command and response encryption and MAC
authentication. The card receipt is verified before the channel becomes
active. Subsequent APDUs use the same short, extended, command-chaining,
response-chaining, counter, padding, and MAC handling as the SCP03 transport.

The shared Rust `Pkcs11Auth` handlers perform ephemeral generation, ECDH,
X9.63 SHA-256, extraction, and receipt verification. Configured OCE private keys
are imported into protected provider session objects after file decryption and
certificate matching. No file-unlock password is retained. The provider session
owns the imported OCE credential; separate handshake sessions own ephemeral
keys and intermediate objects.

The client prefers a native protected session-object graph, then combined
derivation with a host-readable agreement prefix, then basic ECDH with the KDF
in zeroizing process memory. A failure executing the selected path is returned
without retrying a weaker path. The protected receipt key verifies the complete
encoded transcript before the four final AES values are read. See
[client ECDH placement and security](client-ecdh-security.md) for the exact
selection rules, host-visible material, SCP11a/b/c differences, and comparison
with native YubiHSM Auth.
S-ENC, S-MAC, S-RMAC, and the derived DEK use zeroizing local storage; temporary
provider objects are released on both success and failure. Dynamic login uses
the same operations on the selected provider key.

The live SCP11 session remains paired with the selected applet across calls.
Selecting another applet or reconnecting destroys the live channel. The
validated card public key is cached separately for the connection and can be
reused by later channel establishment.
Recreation defaults to enabled for configured and dynamic channels and can be
disabled with `ccid.recreate_sessions=false`. It does not restore applet PIN
authorization.

## Issuer SD key provisioning

On physical YubiKeys, installing custom SCP11 authentication credentials can
remove the factory SCP03 key set. Before provisioning, establish and verify a
separate, recoverable custom administrative credential. An in-memory test
credential is insufficient as the only recovery path if the process exits.
SCP03 and SCP11 credentials can coexist, but the factory SCP03 bootstrap key
set must not be treated as a persistent recovery credential.

The Swift iPhone smoke app defaults to SCP11b and calls ordinary `C_Login`
for Issuer SD. SCP11a is selected through
`PKCS11RS_CCID_SECURE_CHANNEL=scp11a` and
`PKCS11RS_CCID_CLIENT_URI=pkcs11:`. It retains the existing host-slot
authorization and reports the established channel and resolved credential through
the same inventory flow as other logins. The app does not perform SCP enrollment;
a matching OCE certificate, card provisioning, and card trust configuration
are prerequisites for SCP11a. See the [iPhone test guide](scp11-ios-smoke.md)
for provisioning, launch settings, and expected diagnostics.

Physical qualification on firmware 5.7.4 is consistent with a shared budget of
three credential entries: one SCP03 set, one SCP11a card key, and one SCP11b
card key fit together. Adding the OCE CA public key as a fourth entry returned
`6A84`. With the factory SCP11b key also installed, adding both custom card keys
likewise failed at the second generation command, regardless of insertion order.
These observations do not imply a separate quota for each SCP11 variant.

The ignored `physical_scp11_coexistence` test requires a saved custom SCP03
recovery configuration and space for both temporary card keys. It verifies
SCP11b while SCP11a is present, removes the test-owned SCP11b key to make room
for the OCE CA, and then verifies SCP11a. Each protocol completes three fresh
handshakes and protected Issuer SD reads. It removes its temporary keys and
compares the complete Security Domain inventory with its initial snapshot.
It does not qualify simultaneous operation of both protocols with the CA and
SCP03 recovery set present, nor the factory Yubico certificate-trust path.

```sh
PKCS11RS_TEST_ISSUER_SD_SOURCE=SERIAL \
PKCS11RS_TEST_SCP_RECOVERY_CONFIG=/path/to/saved-custom-scp03.json \
cargo test --lib physical_scp11_coexistence -- --ignored --nocapture
```

The custom recovery set must already be installed and its configuration saved
before this test runs. The test refuses factory KVN `255` and never removes its
recovery set. Its host certificate uses key-agreement usage, subject and authority
key identifiers, and critical GlobalPlatform OCE policy
`1.2.840.114283.100.0.10.2.1.0`, following
[Yubico's hardware-test certificate profile](https://github.com/Yubico/yubikey-manager/blob/main/tests/files/scp/generate_files.sh).
The matching CA identifier is stored on the card. Host private keys remain
temporary provider objects; the saved recovery set permits cleanup after a
process failure without retaining the temporary host credential.

The ignored `physical_scp11a_with_yubihsm_host` variant generates a temporary
nonextractable P-256 token key on a physical YubiHSM and issues the OCE
certificate from its public point. It borrows that key through an authorized
`Pkcs11Auth` provider session. The test verifies that the private scalar cannot
be read, the key exists in the native HSM inventory, and the prefixed-ECDH
mechanism is permitted. Three fresh SCP11a handshakes and protected reads have
been qualified against a physical YubiKey with this source. The private scalar
stays in the HSM; the physical YubiHSM backend completes the prefixed KDF in
the module, and channel message cryptography uses the final local working keys.

This variant also requires `PKCS11RS_TEST_SCP_HOST_HSM` and
`PKCS11RS_TEST_SCP_HOST_HSM_PIN`, in addition to the card serial and saved SCP03
configuration above. Supply the source PIN through a secret-input wrapper, not
as a literal shell argument. The existing HSM Auth helper must be available; the
test enables its applet on the selected YubiKey. Both native device inventories
are checked after temporary-key cleanup. No source PIN is retained for session
recreation, and the saved SCP03 recovery set remains installed.

`pkcs11rs.h` declares typed administration functions for SCP11 keys and trust
data. They require a read/write session on the Issuer SD slot and an existing
`CKU_USER` login over an OCE-authenticated channel. SCP03, SCP11a, and SCP11c
authenticate the OCE. SCP11b authenticates only the card and is rejected for
all administration functions.

`PKCS11RS_SecurityDomainGenerateScp11Key` generates an EC private key on the
device and returns its uncompressed SEC1 public point. A null output pointer
queries the required point length without generating a key. The curve values
declared in `pkcs11rs.h` match Yubico's Security Domain curve IDs.

`PKCS11RS_SecurityDomainPutScp11PrivateKey` accepts one transient canonical
PKCS #8 DER EC private key. The authenticated secure channel protects it in
transit, and the private scalar is wrapped using the channel DEK before
device storage. The function returns `CKR_KEY_FUNCTION_NOT_PERMITTED` when the
channel has no DEK. `PKCS11RS_SecurityDomainPutScp11PublicKey` accepts a
canonical DER SubjectPublicKeyInfo EC public key and does not require a DEK.
Temporary private-key material is zeroized.

`PKCS11RS_SecurityDomainStoreScp11CertificateChain` accepts DER X.509
certificates in issuer-to-leaf order and verifies that each issuer signs the
next certificate before sending anything. The CA issuer function stores a
Subject Key Identifier, and the allowlist function stores positive certificate
serial numbers for SCP11a or SCP11c. Passing an empty allowlist clears it.

`PKCS11RS_SecurityDomainDeleteScp11Key` deletes exactly one nonzero KID/KVN
reference. It does not expose the GlobalPlatform wildcard deletion behavior.
Successful mutations invalidate and refresh the Issuer SD object inventory.
Raw `STORE DATA` and Security Domain reset are deliberately not exposed.

## Read-only SCP qualification

The ignored `card_scp_protected_reads_across_operations` test uses the selected
card's existing keys. It opens three fresh sessions, performs PIN-free Issuer
SD logins, and verifies three protected key-information/CPLC read pairs per
session. Qualification requires a stable 42-byte CPLC value on both targets.
The virtual card uses the legacy field layout with a synthetic IC serial
derived from its configured device serial and unspecified production metadata.
The client accepts both raw YubiKey
responses and the conventional `9F7F 2A` TLV wrapper.
Physical qualification uses a factory firmware 5.7.4 YubiKey. Embedded virtual
qualification verifies public CPLC reads, persistence reload, and three fresh
SCP03 and SCP11b sessions with three protected reads each. An attached USB
virtual target must run a worker build with the CPLC handler. These tests do
not provision or replace physical keys.

### Public Issuer SD data objects

`GET DATA` (`CA`) selects an object with the two-byte `P1-P2` value. For
GlobalPlatform class `80`, the response includes the outer BER-TLV tag and
length; ISO class `00` returns its value. The virtual Issuer SD supports both
response forms for its implemented objects.

A public, unauthenticated scan of all 65,536 `P1-P2` values with class `80`
on physical YubiKey serial 36707396, firmware 5.7.4, identifies these objects:

| Selector | Object | Observed behavior |
| --- | --- | --- |
| `0066` | Card Recognition Data | Readable; advertises protocol implementation options |
| `00E0` | Key Information Template | Readable; lists existing SCP keys |
| `9F7F` | CPLC | Readable; 42-byte value |
| `BF21` | Card certificate bundle | Requires `A6 {83 KID KVN}`; factory `13/01` returns certificates |
| `FF34` | Card CA identifiers | Readable; identifies the issuer associated with `13/01` |

The scan returns `9000` for the four objects without parameters, `6A80` for
`BF21` without its required selector, and `6A88` for all other selectors.
Targeted reads confirm the class `00`/`80` response distinction, including the
parameterized `BF21` request. `FF33` has no advertised host CA on this factory
configuration, so `0083` lookup of a provisioned host CA cannot be qualified
from these results. An absent or parameter-dependent response does not prove
that a feature is unsupported after provisioning or authentication.

The virtual Issuer SD implements all five observed objects, plus `FF33`
host CA identifiers and `83` host CA lookup using `A6 {42 CA-ID}`. The
factory card advertises its signing root's SKI through `FF34`; configured
certificate-backed host CAs supply their root SKI through `FF33`. Explicit
issuer identifiers retain precedence, and raw CA public-key imports need
their identifier stored separately. Unknown host identifiers return `6A88`,
malformed selectors return `6A80`, and duplicate host identifiers return
`6985`. Lookup returns a KID/KVN value for class `00` and an `83` TLV for
class `80`. Replacement or deletion removes the old identifier association.
Older saved factory identities and configured host CAs recover missing
metadata without changing their card keys or stored certificate chains.

Virtual recognition data follows the Security Domain format, advertising
SCP03 option `60` and SCP11 option bytes `9B 06`. It omits optional full-card
management-version and IIN/CIN claims. Qualification checks all five factory
objects over SCP03 and SCP11b in both response forms, including long
certificate-response chaining; provisioned virtual SCP11a/c tests check
host-CA inventory and lookup publicly and through their established channels.
Public inventory is distinct from SCP establishment and does not prove
whether an uploaded OCE public key is retained.
The physical key's SCP11 implementation option is encoded as `9B 06` in its
recognition OID. Bit 3 of its first option byte is clear, so it does not
advertise persistent OCE public-key storage. This agrees with sending the
OCE chain before each handshake; persistence across selection or power loss
has not been independently exercised with a provisioned host credential.

The object definitions and response forms are specified in
[GlobalPlatform Card Specification public review v2.3.1.49, section 11.3](https://globalplatform.org/wp-content/uploads/2025/05/GPC_CardSpecification_v2.3.1.49_PublicRvw.pdf)
and [SCP11 public review v1.3.0.13, section 7](https://globalplatform.org/wp-content/uploads/2023/08/GPC_2.3_F_SCP11_v1.3.0.13_PublicRvw.pdf).
These public review documents do not establish that every generic
GlobalPlatform object is implemented by YubiKey. Yubico documents SCP03 from
firmware 5.3.0 and SCP11 from 5.7.2 in its
[technical manual](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-scp.html).

Select one card explicitly and constrain discovery to its Issuer SD:

```sh
PKCS11RS_TEST_ISSUER_SD_SOURCE=YOUR_SERIAL \
PKCS11RS_SLOTS_SERIALS=YOUR_SERIAL \
PKCS11RS_CCID_APPLICATIONS=issuer-sd \
PKCS11RS_CCID_SECURE_CHANNEL=scp11b \
cargo test -p pkcs11rs --lib --features embedded-virtual-yubikey \
  card_scp_protected_reads_across_operations -- --ignored --nocapture --test-threads=1
```

Use `scp03` to test factory SCP03 instead. Virtual SCP11b testing requires its
own explicitly configured CA certificate. The
[iPhone smoke app](../examples/ios/PKCS11RSPhoneSmoke/README.md) configures
SCP11b for its ordinary CCID logins over CryptoTokenKit. Public inventory alone
does not establish a channel; the module establishes it during login.

## SCP11b hardware provisioning test

The ignored `provisions_and_authenticates_scp11b_key` test generates a
persistent P-256 SCP11b key, issues and stores an issuer-to-leaf certificate
chain using the repository's test CA, rediscovers both objects, and completes
an SCP11b-protected Issuer SD `GET DATA`. It refuses to replace an existing
KID `0x13` key and leaves the new key and certificates installed.

Choose an unused nonzero KVN and explicitly enable the destructive test:

```sh
PKCS11RS_TEST_PROVISION_SCP11B=1 \
PKCS11RS_TEST_SCP11B_KVN=2 \
PKCS11RS_CCID_SECURE_CHANNEL=scp03 \
cargo test provisions_and_authenticates_scp11b_key -- --ignored --nocapture
```

The provisioning channel must authenticate the OCE, so it may use SCP03,
SCP11a, or SCP11c, but not SCP11b. Configure its keys as described above and
in [`scp03.md`](scp03.md). When multiple YubiKeys are attached, set
`PKCS11RS_TEST_ISSUER_SD_SOURCE` to the desired serial number or full reader
name. The embedded CA private key and resulting certificates are test material
only.
