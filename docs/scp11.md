# SCP11a, SCP11b, and SCP11c configuration

Set `PKCS11RS_CCID_SECURE_CHANNEL=scp11b` to establish an SCP11b secure
channel for the selected CCID applet on a PC/SC card. See
[`ccid.md`](ccid.md) for the default applet list, allowlist, AID overrides, and
shared-slot behavior. YubiKey SCP11 support requires firmware 5.7.2 or later.

Set `PKCS11RS_CCID_SECURE_CHANNEL=scp11a` to use SCP11a instead. SCP11a adds
mutual authentication and requires the OCE credentials described below.

Set `PKCS11RS_CCID_SECURE_CHANNEL=scp11c` to use SCP11c. It uses the same OCE
credentials as SCP11a, with the SCP11c key referenced by KID `0x15`.

The Issuer SD is used separately for Secure Domain management.

SCP11b authenticates the card to the host. On a stock YubiKey with firmware
5.7.4 or later, the module validates the Security Domain certificate chain
against its embedded Yubico Attestation Root 1. This supports the factory
SCP11b identity without additional trust configuration.

Custom-provisioned devices may override the factory trust anchor using exactly
one of:

- `PKCS11RS_SCP11_SD_PUBLIC_KEY`: the 65-byte uncompressed SEC1 public point,
  encoded as hexadecimal;
- `PKCS11RS_SCP11_SD_CA_CERTIFICATE`: path to the PEM or DER X.509 CA
  certificate that authenticates the SD certificate chain.

In factory or configured CA-certificate mode, the module temporarily selects
the Issuer SD, reads the chain for the configured SCP11 KID/KVN, and reselects
the target applet. OpenSSL validates the chain against the selected CA,
including validity periods and CA constraints, before the leaf P-256 key is
used for SCP11 authentication. The SCP11 receipt then proves that the card owns
the matching private key. The module never implicitly trusts a certificate
obtained from the card.

Optional configuration:

- `PKCS11RS_SCP11_KEY_VERSION`: decimal or `0x` key version, default `1`;

SCP11a and SCP11c additionally require:

- `PKCS11RS_SCP11_OCE_PRIVATE_KEY`: path to a PEM or DER P-256 private key;
- `PKCS11RS_SCP11_OCE_CERTIFICATES`: one or more certificate paths separated by
  the platform path separator, ordered from issuer to leaf;
- `PKCS11RS_SCP11_OCE_KEY_VERSION`: OCE key version, default `0`;
- `PKCS11RS_SCP11_OCE_KEY_ID`: OCE key identifier, default `0`.

The leaf certificate public key must match the configured OCE private key, and
each certificate must verify the next certificate in the configured chain.

The SCP11b transport uses NIST P-256 ephemeral key agreement and KID `0x13`.
The SCP11a and SCP11c transports upload the OCE certificate chain, use KID
`0x11` and `0x15` respectively, and combine ephemeral and static ECDH. All use
AES-128 session keys and the
mandatory `0x33` security level with command and response encryption and MAC
authentication. The card receipt is verified before the channel becomes
active. Subsequent APDUs use the same short, extended, command-chaining,
response-chaining, counter, padding, and MAC handling as the SCP03 transport.

## Issuer SD key provisioning

`pkcs11rs.h` declares typed administration functions for SCP11 keys and trust
data. They require a read/write session on the Issuer SD slot and an existing
`CKU_USER` login over an OCE-authenticated channel. SCP03, SCP11a, and SCP11c
authenticate the OCE. SCP11b authenticates only the card and is rejected for
all administration functions.

`PKCS11RS_SecurityDomainGenerateScp11Key` generates an EC private key on the
device and returns its uncompressed SEC1 public point. A null output pointer
queries the required point length without generating a key. The curve values
declared in `pkcs11rs.h` match Yubico's Security Domain curve IDs.

`PKCS11RS_SecurityDomainPutScp11PrivateKey` accepts an unencrypted DER PKCS#8
or traditional EC private key. The private scalar is wrapped using the current
static DEK, so the function returns `CKR_KEY_FUNCTION_NOT_PERMITTED` when the
authenticated channel has no DEK. `PKCS11RS_SecurityDomainPutScp11PublicKey`
accepts a DER SubjectPublicKeyInfo EC public key and does not require a DEK.
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
