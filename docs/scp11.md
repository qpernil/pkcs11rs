# SCP11a and SCP11b configuration

Set `PKCS11RS_CCID_SECURE_CHANNEL=scp11b` to establish an SCP11b secure
channel for the selected CCID applet on a PC/SC card. See
[`ccid.md`](ccid.md) for the default applet list, allowlist, AID overrides, and
shared-slot behavior. YubiKey SCP11 support requires firmware 5.7.2 or later.

Set `PKCS11RS_CCID_SECURE_CHANNEL=scp11a` to use SCP11a instead. SCP11a adds
mutual authentication and requires the OCE credentials described below.

The Issuer SD is used separately for Secure Domain management.

SCP11b authenticates the card to the host. This implementation requires the
expected P-256 Security Domain public key to be pinned using exactly one of:

- `PKCS11RS_SCP11_SD_PUBLIC_KEY`: the 65-byte uncompressed SEC1 public point,
  encoded as hexadecimal;
- `PKCS11RS_SCP11_SD_CERTIFICATE`: path to a PEM or DER X.509 certificate whose
  P-256 public key is the expected `CERT.SD.ECKA` key.

The certificate file is treated as pinned configuration. The implementation
does not fetch and implicitly trust an unverified certificate from the card.
Certificate-chain validation and provisioning remain the caller's
responsibility.

Optional configuration:

- `PKCS11RS_SCP11_KEY_VERSION`: decimal or `0x` key version, default `1`;

SCP11a additionally requires:

- `PKCS11RS_SCP11_OCE_PRIVATE_KEY`: path to a PEM or DER P-256 private key;
- `PKCS11RS_SCP11_OCE_CERTIFICATES`: one or more certificate paths separated by
  the platform path separator, ordered from issuer to leaf;
- `PKCS11RS_SCP11_OCE_KEY_VERSION`: OCE key version, default `0`;
- `PKCS11RS_SCP11_OCE_KEY_ID`: OCE key identifier, default `0`.

The leaf certificate public key must match the configured OCE private key, and
each certificate must verify the next certificate in the configured chain.

The SCP11b transport uses NIST P-256 ephemeral key agreement and KID `0x13`.
The SCP11a transport uploads the OCE certificate chain, uses KID `0x11`, and
combines ephemeral and static ECDH. Both use AES-128 session keys and the
mandatory `0x33` security level with command and response encryption and MAC
authentication. The card receipt is verified before the channel becomes
active. Subsequent APDUs use the same short, extended, command-chaining,
response-chaining, counter, padding, and MAC handling as the SCP03 transport.
