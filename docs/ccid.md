# CCID applet configuration

The PC/SC transport automatically probes these CCID applets by default:

| Applet | Default AID | AID override |
| --- | --- | --- |
| PIV | `A0 00 00 03 08` | `PKCS11RS_PIV_AID` |
| OpenPGP | `D2 76 00 01 24 01` | `PKCS11RS_OPENPGP_AID` |
| YubiHSM Auth | `A0 00 00 05 27 21 07 01` | `PKCS11RS_HSMAUTH_AID` |
| GlobalPlatform | `A0 00 00 01 51 00 00 00` | `PKCS11RS_GLOBALPLATFORM_AID` |

Each applet is added as a separate PKCS #11 slot only when its configured AID
can be selected successfully. Initialization and object-discovery failures do
not remove an already discovered slot; they leave it enumerated with the token
marked not-present. The next refresh retries discovery.

## Allowlist

Without configuration, all four applets above are probed. Set
`PKCS11RS_CCID_APPLICATIONS` to a comma-separated allowlist when only specific
applets should be exposed:

```text
PKCS11RS_CCID_APPLICATIONS=piv,openpgp
```

Accepted names are `piv`, `openpgp` (or `pgp`), `hsmauth` (or
`yubihsm-auth`), and `globalplatform` (or `global-platform` or `gp`). Names
are case-insensitive and duplicates are ignored.

## Secure channels

Set `PKCS11RS_CCID_SECURE_CHANNEL` to `scp03`, `scp11a`, or `scp11b` to use
that transport for every selected CCID applet. The secure channel is scoped to
the selected AID. Selecting another applet invalidates the previous channel,
so the module selects the requested AID and renegotiates before sending the
next protected command.

The reader connection is shared between all applet slots. GlobalPlatform is
the Secure Domain management applet; it is not required to use PIV, OpenPGP,
or YubiHSM Auth.

Protocol-specific key and certificate configuration is documented in
[`scp03.md`](scp03.md) and [`scp11.md`](scp11.md).
