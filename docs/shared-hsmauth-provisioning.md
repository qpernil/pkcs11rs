# Shared symmetric YubiHSM Auth provisioning

The ignored Rust test `provisions_shared_symmetric_hsmauth` provisions one
random AES-128 ENC/MAC pair into explicitly selected YubiKeys and directly
attached YubiHSMs. It creates a general authentication credential with the
domains, capabilities, and delegated capabilities of the existing HSM
credential used to authorize provisioning. If that credential is an
administrator, the new credential also has administrator authority.

The helper does not reset devices, overwrite credentials, or contact configured
remote HSM URLs. Every selected YubiKey must be present, and the complete local
HSM inventory must match the requested serial numbers. Existing labels and
authentication-key IDs cause failure before importing keys. The new credential
has touch disabled. The helper requires explicit secrets; it supplies no
factory credential defaults.

## Inputs

Set these environment variables for the provisioning process:

| Variable | Value |
| --- | --- |
| `PKCS11RS_SHARED_SOURCES` | Comma-separated exact connector names, such as `YubiKey CCID #37070618,YubiKey CCID #37987918` |
| `PKCS11RS_SHARED_HSMS` | Comma-separated decimal serials of all locally attached HSMs |
| `PKCS11RS_SHARED_LABEL` | New, unused credential label, 1–40 bytes |
| `PKCS11RS_SHARED_ID` | New, unused HSM authentication-key ID, four hexadecimal digits |
| `PKCS11RS_SHARED_ADMIN_SOURCE` | One of the exact selected YubiKey connector names |
| `PKCS11RS_SHARED_ADMIN_LABEL` | Existing HSM Auth credential that authenticates to every target HSM |
| `PKCS11RS_SHARED_ADMIN_ID` | Its matching HSM authentication-key ID, four hexadecimal digits |
| `PKCS11RS_SHARED_ADMIN_PASSWORD` | Existing credential password |
| `PKCS11RS_SHARED_PASSWORD` | Password for the new credential, at most 16 bytes |
| `PKCS11RS_SHARED_MANAGEMENT_KEY` | Current management key common to the selected applets, 32 hexadecimal digits |

Without `PKCS11RS_SHARED_APPLY=1`, the command authenticates and inspects
inventories and permissions, then closes the sessions without importing keys:

```sh
cargo test --locked -p pkcs11rs --lib provisions_shared_symmetric_hsmauth -- \
  --ignored --nocapture
```

Set `PKCS11RS_SHARED_APPLY=1` only for the intended persistent installation.
Provisioning checks the credential and HSM object inventories after import,
then authenticates and exchanges an encrypted echo from every selected
YubiKey to every selected HSM. Clear the secret environment variables after
the process exits. The helper holds its copies in zeroizing memory and does
not save the random ENC/MAC keys to disk or print them.

Preflight cannot validate the applet management key without an authenticated
administration operation. A later device failure can therefore leave a partial
installation. The helper prints each completed addition and stops on failure;
it does not automatically delete anything or persist keys for a later retry.
Inspect a partial installation before recovery. A retry with existing labels
or IDs is refused. Removal during recovery must be limited to additions known
to belong to that failed run. Adding another device later requires a separate
key distribution plan because this helper keeps no host backup.

## Verified local configuration

Credential `shared` is installed on YubiKeys **37070618** and **37987918**.
Authentication key **1006** is installed on local HSMs **1238075073** and
**2545354682**, with all domains and full capabilities and delegated
capabilities inherited from key **1001**. Touch is disabled. All four
YubiKey-to-HSM authentication combinations were verified; existing credentials
and HSM objects were preserved. Other YubiKeys and remote HSMs are outside
this configuration.

When both YubiKeys are connected, select the source explicitly in the PKCS #11
login string: `:1006shared@37070618:<credential-password>` or
`:1006shared@37987918:<credential-password>`. With only one matching applet,
`:1006shared:<credential-password>` is sufficient. Supply the login through
the client's PIN input mechanism; do not store it in project files.
