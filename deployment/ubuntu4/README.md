# build-host lab connector

Hostnames and device/account identifiers below are illustrative; replace them with your own configured values.

These files describe the verified lab service, not a general network deployment.
The base unit belongs at `/etc/systemd/system/pkcs11rs-connector.service`; the
override belongs at `pkcs11rs-connector.service.d/20-i2c.conf` alongside it.
The explicit insecure HTTP listener is for the existing trusted lab network.
The service account belongs to `dialout` and `i2c` for USB/I2C/GPIO access.

Build the connector from the verified Git checkout on build-host:

```sh
cargo build --locked --release -p pkcs11rs-connector \
  --features experimental-i2c,firmware-full
```

First-party path dependencies must also be clean, published Git checkouts.
The [bench record](https://github.com/qpernil/raspberry-pi-i2c-target/blob/main/docs/bench-validation-2026-11-01.json)
records the tested source revisions and installed binary hash. There is no
committed connector prebuilt. Build changes on build-host; do not run Rust builds
on the two Pi3 target machines.

Both I2C targets persist across service restarts: serial `24000001` at `0x24`
uses controller GPIO23, and serial `25000002` at `0x25` uses GPIO22. Both READY
inputs use pull-ups; each target GPIO17 drives low or releases. Ordinary USB
discovery stays enabled. No pad-strength or slew override is installed.

Embedded HSM `99000001` is disabled by omitting `--virtual-yubihsm` from both
the base unit and override. `firmware-full` remains compiled for test support.
The existing state directory is retained, with a root-only backup; disabling
the endpoint does not delete its objects or state.

To disable I2C temporarily while retaining its configuration, rename the whole
`20-i2c.conf` file to `20-i2c.conf.disabled`, run `systemctl daemon-reload`, and
restart the connector. Restore the `.conf` suffix to re-enable it. Commenting
only the command after the empty `ExecStart=` leaves an invalid service. There
is no separate I2C-enable boolean; a serial filter is not a substitute for
disabling probing. This operation leaves USB discovery enabled and does not
re-enable the embedded HSM.

After any intentional installation, run `systemd-analyze verify`, confirm the
service is enabled and active, and inspect `/v1/devices` for the expected four
claimed USB/I2C devices and no embedded serial. Preserve all HSM state directories
and existing credentials. Shared-bus reliability and authenticated/PQC recovery
remain subject to the [qualification limits](../../docs/i2c-stability.md).
