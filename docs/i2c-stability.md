# Experimental I2C HSM transport requirements and validation

The Linux I2C YubiHSM transport is intended for niche hardware experiments.
It requires the connector's `experimental-i2c` build feature and explicit
endpoint configuration. The single-flight request/response protocol runs
between a controller using `i2c-dev` and a Raspberry Pi BSC target. A compatible
deployment uses the `raspberry-pi-i2c-target` driver ABI 3 with its READY request handshake and the controller implementation in
`pkcs11rs-connector/src/i2c/`. PKCS #11 applications and the qualification
tool access I2C HSMs through the connector's HTTP API.

## Oscilloscope experiments

Use an oscilloscope such as the Siglent SDS824X HD to capture SCL and SDA
together with READY. Inspect request/response traffic, response latency,
header/body pauses, and response completion.

Record the measured SCL rate separately from the configured adapter rate;
Pi 4 clock scaling can make the actual rate differ from the configured rate.
Follow the target driver's
[hardware and oscilloscope validation plan](https://github.com/qpernil/raspberry-pi-i2c-target/blob/main/docs/hardware-test-plan.md)
for wiring, signal-integrity checks, and evidence to retain. These experiments
provide lab evidence for a particular setup, not general electrical qualification.

## Exchange contract

Use driver ABI 3 with READY configured on both ends. The controller holds the
bus lock from request writing through the target's cleanup acknowledgment
(physical rising READY edge), releases it while waiting for computation, then
reacquires it for the three-byte header and exact-length body reads. A per-device
gate keeps each HSM single-flight. Separate targets can compute concurrently,
but shared-bus concurrency remains unqualified.
READY stays asserted after reading; a new request clears previous transmit state. The
acknowledgment includes a short assertion when READY was already inactive,
so the controller waits for an edge rather than trusting an old level. It arms
rising-only detection before writing, then falling-only detection followed by
a level check for the response. Linux both-edge reporting can misclassify the
short inactive interval by sampling the pin after the response is already ready.

Only actual response bytes are queued. A new request invalidates the previous
result and replaces the single pending request; an older computation may finish
but cannot publish its stale result. This restores synchronization without
undoing side effects or making replay of uncertain commands safe.

A physical Pi 3B+ test queued A1 B2 C3 without a driver or guard: after reading
two bytes, FIFO level and TXBUSY were both zero, but the next read returned C3.
The flags remained identical after that final byte. Queuing and reading another
complete response without a reset succeeded. This is why the driver avoids
inferring completion and clears transmit state at the next request instead.

All bus clients must cooperate in the advisory lock. Target activation, close
and unload still require quiescent bus traffic. Linux IRQ latency and electrical
margins remain hardware qualification concerns.

## Validation

The actual C driver functions pass FIFO/serializer model checks for staged reads,
abandoned last bytes, superseded worker results, receive-tail completion and
transmit-refill latency. The target repository passes 27 Rust unit tests and
Clippy with warnings denied. Both Pis build the kernel module against their
running kernel.

The connector's Linux I2C build passes 61 unit tests; the production firmware
feature combination passes 67. Both pass Clippy with warnings denied. Its Mac
I2C-targeted suite passes nine tests. The connector and raw stress tool disable
implicit adapter retries under each wire-phase lock. Other bus clients must preserve this adapter-wide policy;
retrying a partially consumed reply also loses framing.

The hardware topology is Ubuntu4 (Pi 5/RP1) controlling raspberrypi-1 (`0x24`,
serial 24000001, READY GPIO23) and raspberrypi-2 (`0x25`, serial 25000002,
READY GPIO22). Targets use GPIO17 for READY and separate qualification state
directories. The finite PQC qualification below uses the original configured
400 kHz rate, approximately 391 kHz during uninterrupted scope clock bursts,
with the original controller SDA hold register `0x00010001`. No timing overlay
or diagnostic kernel probe is installed.

## PQC provider qualification

The deployed `pqc_matrix_deployed_yubihsm` suite passes single-target baselines
on both I2C targets through Ubuntu4's connector. Concurrent shared-bus operation
remains unqualified. The suite uses the existing Secure Enclave `reserve`
credential and Authentication Key `1003`, without changing credentials or
discovery-role permissions. The signed macOS test host has the credential's Keychain access
group; local hardware discovery is disabled.

Coverage includes ML-DSA-44/65/87, ML-KEM-512/768/1024, and the three concrete
hybrid KEMs (`MLKEM768-P256`, `MLKEM768-X25519`, `MLKEM1024-P384`). The matrix
checks token key generation, pure and prehashed signatures, multipart operations,
contexts and hedging, signature rejection, KEM buffer retries, secret agreement,
invalid ciphertexts, and mismatched hybrid constructions. Standalone expanded-key
import tests remain separate from this deployed matrix.

The fixture refuses occupied IDs in `7e40`–`7e48` and removes its temporary
public and private objects. Read-only inventory comparisons verify preservation
of all existing objects: 56 on serial `24000001` and 17 on serial `25000002`.
See the [qualification record](i2c-pqc-qualification.json) for the tested revision,
individual results, source revisions, inventory digests and concurrency limits.

### Qualification limits

Shared-bus concurrency reproduces NACKs, arbitration loss, truncated requests
and full-length replies that fail MAC verification. Failures occur while the
bus lock is released during computation and response publication. Independent
SDK reads and ordinary echo requests reproduce failures too. A captured
2,444-byte reply differs from the target's output after its first 187 bytes,
without a recorded FIFO underrun.

The qualification record retains a historical complete-exchange serialization
experiment: three paired rounds passed all six matrices, each in approximately
250–254 seconds, with the exact 56/17-object baseline inventories preserved.
Targets reported zero receive overruns, drops and transmit underruns, and the
validation connector reported no error outcomes. That workaround is excluded
from the implementation; its results do not qualify the retained concurrency
behavior.

The precise peripheral or electrical mechanism is not established. Scope ringing
alone does not demonstrate a threshold crossing. Reducing the rate to 100 kHz
or increasing controller SDA hold did not qualify pipelined operation. The
receive-tail fix corrects a reproduced driver race, and earlier transmit refill
improves tolerance of interrupt latency; they do not by themselves resolve
pipelined shared-bus failures.

An interrupted generation can leave a device key and PKCS #11 metadata even
when the API returns an error. Do not blindly replay the operation. Compare
the inventory with the pre-run snapshot, establish a fresh authorized session,
and remove only proven test-owned objects. Delete an owned public projection
before its private key so cleanup does not retain a detached public object.

## Reproduction

Stop the connector before the raw tool claims its READY lines:

```sh
python3 tools/i2c-stress.py 0x24 --ready /dev/gpiochip0:23 --count 1000 --payload-gap-ms 5
python3 tools/i2c-stress.py 0x25 --ready /dev/gpiochip0:22 --count 1000 --abandon-every 10
```
