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

SCP11b authenticates the card to the host. This implementation requires the
expected P-256 Security Domain public key to be pinned using exactly one of:

- `PKCS11RS_SCP11_SD_PUBLIC_KEY`: the 65-byte uncompressed SEC1 public point,
  encoded as hexadecimal;
- `PKCS11RS_SCP11_SD_CERTIFICATE`: path to a PEM or DER X.509 certificate whose
  P-256 public key is the expected `CERT.SD.ECKA` key.

The certificate file is treated as pinned configuration. The implementation
does not fetch and implicitly trust an unverified certificate from the card.
Choosing the trusted certificate chain remains the caller's responsibility.

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
