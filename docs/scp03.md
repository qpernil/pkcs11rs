# SCP03 configuration

Set `PKCS11RS_CCID_SECURE_CHANNEL=scp03` to use SCP03 as the transport for
the selected CCID applet on a PC/SC card. See [`ccid.md`](ccid.md) for the
default applet list, allowlist, AID overrides, and shared-slot behavior.

For the Issuer SD, the selected AID is the Secure Domain used for
management. For PIV and OpenPGP, the transport initializes against those
applets' AIDs directly.

The PC/SC CCID path selects an application and establishes an SCP03 channel
during `C_Login`. The channel is scoped to the selected application and is
renegotiated when another applet is selected.

SCP03 configuration is supplied as hexadecimal environment variables:

- `PKCS11RS_SCP03_ENC_KEY` (optional direct static key)
- `PKCS11RS_SCP03_MAC_KEY` (optional direct static key)
- `PKCS11RS_SCP03_DEK_KEY` (optional for transport; required for key-set provisioning)
- `PKCS11RS_SCP03_BMK` (optional Yubico Batch Master Key)
- `PKCS11RS_SCP03_KEY_VERSION` (optional decimal or `0x` byte, default `255`)
- `PKCS11RS_SCP03_KEY_ID` (optional decimal or `0x` byte, default `0`)
- `PKCS11RS_SCP03_SECURITY_LEVEL` (optional, default `0x33`)

When none of ENC, MAC, DEK, or BMK is configured, key version `255` uses the
YubiKey factory test value `40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F`
for all three keys. This publicly known value is suitable only for initial
provisioning and testing and should be replaced before deployment. If any
direct key is configured, both ENC and MAC are required. BMK and direct keys
are mutually exclusive.

With a 256-bit `PKCS11RS_SCP03_BMK`, the card-specific 128-bit ENC, MAC, and DEK
values are derived using the Yubico AES-CMAC SP800-108 counter-mode layout and
labels `00000001`, `00000002`, and `00000003`. The issuer context is taken from
the first ten bytes returned by `INITIALIZE UPDATE`. It is not taken from CPLC.
YubiKey CPLC is a separate 42-byte diagnostic object returned by `GET DATA 9F7F`,
and Yubico assigns meaning only to its first two chipset bytes.

YubiKey 5 defaults use security level `0x33` and AES-128 keys. Explicit generic
SCP03 configurations may still select security levels `0x00`, `0x01`, `0x03`,
`0x11`, `0x13`, or `0x33`, and AES-128, AES-192, or AES-256 direct keys are
accepted. Key values are never included in debug output, and derived
transport and session keys are zeroized when the PKCS #11 login ends.

This implementation currently supports SCP03 S8 mode. It validates the
card's `i` parameter, verifies pseudo-random card challenges using the
three-byte sequence counter and selected Security Domain AID, and rejects
R-MAC or response-encryption levels that the card does not advertise. S16
mode is rejected until its 16-byte challenge, cryptogram, and MAC framing is
implemented.

The APDU codec supports short and extended Case 2, 3, and 4 commands. It
automatically uses extended encoding when command data exceeds 255 bytes or
when SCP03 encryption, padding, and C-MAC increase the protected data beyond
that boundary. Extended responses use the PC/SC extended receive-buffer size.
Secure messaging currently operates on basic logical channel 0; commands for
other logical channels are rejected.

GlobalPlatform command chaining is also supported for commands whose
protected data exceeds the short APDU limit. Encryption and C-MAC are applied
once to the complete logical command before it is split into 255-byte data
fields. Intermediate commands set the `P1.b8` "more commands" bit, omit `Le`,
and require an empty `9000` response without R-MAC. The C-MAC is carried only
in the final command. The card command itself must support this chaining
mechanism, as DELETE, INSTALL, and PUT KEY do in the GlobalPlatform Card
Specification.

ISO response chaining via `61xx` is collected with unprotected GET RESPONSE
commands. SCP03 response decryption and R-MAC verification are then performed
once over the reassembled non-segmented response. A chain is limited to 256
continuation segments, and every continuation after the initial `61xx` must
contribute response data.

## Issuer SD key provisioning

`pkcs11rs.h` declares an administration ABI for loading and deleting SCP03 key
sets. Initialize the module, open a read/write session on the Issuer SD slot,
and call `C_Login` to establish SCP03 before using either function:

```c
PKCS11RS_SCP03_KEY_SET keys = {
  .pEncKey = enc, .ulEncKeyLen = 16,
  .pMacKey = mac, .ulMacKeyLen = 16,
  .pDekKey = dek, .ulDekKeyLen = 16,
};

CK_RV rv = PKCS11RS_SecurityDomainPutScp03KeySet(
  session, new_kvn, replace_kvn, &keys
);
```

The function follows the Yubico `PUT KEY` format. All three AES-128 components
are wrapped with the current static DEK using AES-CBC with a zero IV. The
three-byte key check values are calculated and verified against the card's
response. Provisioning returns `CKR_KEY_FUNCTION_NOT_PERMITTED` when the
authenticated channel has no static DEK, including an SCP11 channel.

`replace_kvn` is zero when adding a key set and identifies the old KVN for an
in-place replacement otherwise. New key sets must use a KVN from 1 through
254; KVN 255 is reserved for the factory key set. Safer rotation adds a new
KVN, reconnects and authenticates with it, and only then calls
`PKCS11RS_SecurityDomainDeleteScp03KeySet` for the old KVN. The deletion API
rejects KVN zero. Its `deleteLast` argument must be `CK_TRUE` to deliberately
delete the final set and trigger the device's last-key behavior.

The administration calls are vendor extensions and are not included in the
standard PKCS #11 function lists. They require a read/write session and an
existing `CKU_USER` login. Key material is never logged, and temporary key
state retained by the secure channel is zeroized on release.
