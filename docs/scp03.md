# SCP03 configuration

Set `PKCS11RS_CCID_SECURE_CHANNEL=scp03` to use SCP03 for the selected CCID
applet over the native CCID transport. See [`ccid.md`](ccid.md) for the
default applet list, allowlist, AID
overrides, and shared-slot behavior.

For the Issuer SD, the selected AID is the Secure Domain used for
management. For PIV and OpenPGP, the transport initializes against those
applets' AIDs directly.

`C_Login` establishes the configured channel before authenticating the target
applet. `C_LoginUser` can instead select protected provider credentials while
its PIN authenticates that applet. Public discovery can precede login;
SCP-required PIN management requires login. The selected AID and live channel
are retained across calls to the same applet. Selecting another applet or
reconnecting destroys the live channel. Recreation defaults to enabled for
both credential paths; it never resubmits an applet PIN or restores lost applet
authorization. See [CCID login-selected channels](ccid.md#login-selected-secure-channels).

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
transport and session keys are zeroized when the selected applet changes or
the card connection ends.

Derivation uses the shared Rust `Pkcs11Auth` handlers behind the public C ABI.
Configured input keys are imported as protected session objects in a temporary
software provider. Batch diversification produces protected ENC, MAC, and DEK
objects without reading their values. Counter-KDF outputs explicitly permit
reading the channel working keys; cryptograms and message AES/CMAC run locally.
The static DEK remains a protected provider binding and wraps administration
payloads through AES-CBC. Its owning session ends with the live card channel.
Dynamic `C_LoginUser` selects an already authorized ordinary provider's token
AES `<name>.enc` key through a PKCS #11 URI, with a required `<name>.mac` and
optional `<name>.dek` in the same source. The keys remain bound provider
objects; the target PIN is never used to authorize the source. Existing
configuration continues to select protocol parameters, including KID, KVN,
and security level. Batch-master-key diversification belongs to the configured
path.

This implementation currently supports SCP03 S8 mode. It validates the
card's `i` parameter, verifies pseudo-random card challenges using the
three-byte sequence counter and selected Security Domain AID, and rejects
R-MAC or response-encryption levels that the card does not advertise. S16
mode is rejected until its 16-byte challenge, cryptogram, and MAC framing is
implemented.

The `yubikey-apdu` wire codec is shared by the host and virtual card. SCP
establishment commands have their own specifications alongside the applet
command sets; the codec itself gives P1/P2 no protocol-specific meaning.
It supports short and extended Case 2, 3, and 4 commands and
automatically uses extended encoding when command data exceeds 255 bytes or
when SCP03 encryption, padding, and C-MAC increase the protected data beyond
that boundary. Extended responses use the reader transport's advertised
maximum response size.
Secure messaging currently operates on basic logical channel 0; commands for
other logical channels are rejected.

Short-only transports use ISO command chaining. Encryption and C-MAC cover
the complete logical command before it is split into 255-byte data fields.
Intermediate fragments set CLA bit `10`, preserve P1/P2, and require an empty
`9000` acknowledgement. The card reassembles the protected command before
verifying its MAC and decrypting it. This matches Yubico's
[SCP pipeline](https://github.com/Yubico/Yubico.NET.SDK/blob/53f2c7cbf1ae3175c41badfc211ef66e5a35d4b1/Yubico.YubiKey/src/Yubico/YubiKey/Scp/ScpConnection.cs)
and [command chaining transform](https://github.com/Yubico/Yubico.NET.SDK/blob/53f2c7cbf1ae3175c41badfc211ef66e5a35d4b1/Yubico.YubiKey/src/Yubico/YubiKey/Pipelines/CommandChainingTransform.cs).
The separate GlobalPlatform P1-based chaining mechanism is not implemented.

ISO `6Cxx` length correction belongs to the transport below SCP. A bare
`6Cxx` permits one retransmission of the wire APDU with corrected `Le`
(`00` means 256). The header, Lc encoding, ciphertext, and command MAC remain
unchanged. The SCP session protects the logical command once; length correction
does not encrypt again, advance its counter or MAC chain again, or negotiate a
new channel. `Le` itself is neither encrypted nor included in the C-MAC.
A second `6Cxx` is returned without further correction. Commands without Le,
intermediate chained commands, transport failures, and malformed error payloads
do not trigger correction. Response authentication failures are not retried.
Error statuses such as `6Cxx` carry neither response data nor R-MAC, as required
by [SCP03 section 6.2.5](https://globalplatform.org/wp-content/uploads/2014/07/GPC_2.2_D_SCP03_v1.1.1.pdf).

Both `61xx` response continuation and `6Cxx` length correction are independent
of T=0/T=1 in [ISO 7816-4:2005 section 5.1.3](https://www.freecalypso.org/pub/GSM/ISO7816/ISO_7816-4_2005.pdf). Their additional role in T=0
APDU-to-TPDU mapping does not restrict their use to T=0. A reader or driver may
perform that mapping internally; pkcs11rs handles statuses that reach its ISO
transport. See [APDU, TPDU and PC/SC protocols](ccid.md#apdu-tpdu-and-pcsc-protocols).
A status alone does not establish where a card checked Le or whether SCP state
was consumed. [GlobalPlatform v2.3 Appendix A.1, p. 213](https://globalplatform.org/wp-content/uploads/2018/03/GPC_Specification_v2.3.pdf#page=213) explicitly describes a
T=0 case 2 command whose prepared response is stored before `6Cxx`; the
corrected command retrieves the stored response through the runtime. Treating
every `6Cxx` as a new logical SCP command is therefore unsupported.

Correction applies to the individual wire exchange. A `6Cxx` from GET RESPONSE
or OATH SEND REMAINING corrects that continuation's Le; it does not resubmit the
application command. A correction on the final command fragment does not repeat
preceding fragments. Extended length encoding is retained when Le shrinks,
preserving any MAC-covered Lc bytes. Advertised reader limits can reduce outer
Le or require ISO command fragmentation, but do not cause new SCP protection.
Explicit extended commands retain their length form; an unsupported form is
rejected rather than silently changing MAC input. T=0 case 4's trailing Le is
removed only at the native PC/SC boundary, below SCP and ISO response handling.
Host regression tests check unchanged
protected bytes, bounded correction, continuations, and a single SCP state
advance followed by a normally authenticated next response. Scripted responses
check host behavior; they do not establish physical card processing order.

Physical qualification on 2026-11-15 used a T=1 YubiKey 5.7.4 with factory
SCP03 and SCP11b for public reads from PIV, OpenPGP, HSM Auth, OATH, Management,
and the Issuer SD with `Le` 1, 2, and 8. All 72 supported logical trials and
their following requests returned `9000`; no `6Cxx` was produced. These trials
verify those reads and channel continuity, but do not qualify length correction
on physical firmware. FIDO selection was unavailable in that configuration.
The SCP key inventory was preserved. Raw wire capture covered 36 trials across
those six applets and both SCP protocols. Every initial response contained
exactly the requested 1, 2, or 8 protected bytes and a `61xx` continuation.
For example, PIV GET VERSION returns three plaintext bytes: R-ENC pads/encrypts
them to 16 bytes and R-MAC adds eight bytes, giving 24 protected response bytes.
With `Le=1`, the card returns one byte plus `6117`, then 23 bytes through GET
RESPONSE. This firmware honors Le as a limit on protected response data; SDK
response collection produces the complete logical response. The two status
bytes are excluded from Le. Command encryption alone does not imply response
encryption: the counted field includes whichever response protection is enabled
by the channel's security level.

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
authenticated channel has no DEK. SCP11 supplies a derived DEK for its
OCE-authenticated administration.

`replace_kvn` is zero when adding a key set and identifies the old KVN for an
in-place replacement otherwise. New key sets must use a KVN from 1 through
127; KVN 255 is reserved for the factory key set. The new-version bound follows Yubico's
[key-set rules](https://docs.yubico.com/yesdk/users-manual/sdk-programming-guide/secure-channel-protocol.html#key-set-rules).
Safer rotation adds a new KVN, reconnects and authenticates with it, and only then calls
`PKCS11RS_SecurityDomainDeleteScp03KeySet` for the old KVN. The deletion API
rejects KVN zero. Its `deleteLast` argument must be `CK_TRUE` to deliberately
delete the final set and trigger the device's last-key behavior.

The administration calls are vendor extensions and are not included in the
standard PKCS #11 function lists. They require a read/write session and an
existing `CKU_USER` login. Key material is never logged, and temporary key
state retained by the secure channel is zeroized on release.
