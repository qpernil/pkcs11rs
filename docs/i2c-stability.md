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

Connector workers enter a FIFO admission queue for each wire phase. Character
handles for the same physical adapter share the queue even through device-node
aliases. A queued peer precedes a busy worker's next acquisition, and expired
waiters remove their positions. The existing exchange deadline covers both
queue and advisory-lock waits. The queue position is released after the
advisory lock is unlocked, including error exits; neither is held during target
computation. Other processes still coordinate through the advisory lock, whose
fairness across processes is not guaranteed by this in-process queue.

Workers handle their waits sequentially: bus admission, request cleanup
acknowledgment, computation READY, then response admission. A worker queued for
the bus has no separate event-loop duty needed by another worker. Blocking
`flock` would avoid the polling race but has no timed-acquisition argument;
closing its descriptor from another thread is not reliable cancellation on
Linux, particularly when duplicates retain the open file description. The
queue preserves bounded admission without asynchronous descriptor closure or
process-wide signal handlers. See the Linux [flock](https://man7.org/linux/man-pages/man2/flock.2.html)
and [close](https://man7.org/linux/man-pages/man2/close.2.html) semantics.

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

The connector's Linux `experimental-i2c` build passes 67 unit tests, including
FIFO admission, deadline cancellation and external advisory-lock exclusion.
The Mac connector build without default features passes 65 tests. Both pass
Clippy with warnings denied. The connector and raw stress tool disable
implicit adapter retries under each wire-phase lock. Other bus clients must preserve this adapter-wide policy;
retrying a partially consumed reply also loses framing.

The hardware topology is Ubuntu4 (Pi 5/RP1) controlling raspberrypi-1 (`0x24`,
serial 24000001, READY GPIO23) and raspberrypi-2 (`0x25`, serial 25000002,
READY GPIO22). Targets use GPIO17 for READY and separate qualification state
directories. The finite PQC qualification below uses the original configured
400 kHz rate, approximately 391 kHz during uninterrupted scope clock bursts,
with the original controller SDA hold register `0x00010001`. No timing overlay
or diagnostic kernel probe is installed.

## Fair-acquisition bench validation

On the documented Pi 5 / two Pi 3B+ bench, FIFO acquisition passes the seeded
3,000-echo workload with the same 8,582,931 payload bytes as the polling-lock
baseline. Maximum individual lock wait is 186 ms rather than 2.74 s; maximum
exchange duration is 739 ms rather than 2.75 s. Total workload time remains
approximately 398–399 s. Median exchange latency rises from 189 ms to
237–251 ms because waiting is distributed between peers instead of allowing
one to run ahead. The p95 falls from 867–882 ms to 558 ms.

Isolated PQC matrices pass on both targets, each returning 406 authenticated
signature frames at each of 2,444, 3,340 and 4,652 bytes. Concurrent matrices
remain unqualified: two paired runs reproduce request/read transport errors.
The repeat records `EAGAIN` during the 0x24 payload read, followed by `EIO` on
0x25's header read; the controller logs lost arbitration and a spurious STOP.
The stopped scope record contains only 306 of the expected 2,441 payload bytes,
with a STOP condition approximately 0.1 microsecond after the peer READY
assertion. Channel/probe skew is uncalibrated. This timing correlation is an
investigation lead, not a demonstrated peripheral, driver or electrical cause;
other peer READY assertions during response reads succeed.

All driver error counters remain zero even during these failures. Those
counters therefore do not establish shared-bus integrity. The fixture IDs were
proven absent before testing; fresh authenticated cleanup restores the exact
99/21-object inventories after failed automatic cleanup. Failed commands are
not replayed. The [validation record](i2c-fairness-validation.json) retains source
revisions, per-target results, frame counts, error phases and evidence limits.

### READY-only isolation

An idle peer's READY transitions reproduce a byte mismatch and request
`EREMOTEIO` errors while the other target runs non-mutating echoes. No requests
or new responses are sent to the toggling peer. Level-only toggling still fails
with its BSC driver unloaded and its SDA/SCL pins as inputs, so FIFO publication
is unnecessary for this reproduction. That disabled-peripheral control uses
push-pull level changes; it does not alone prove an identical electrical
mechanism to the original open-drain edge. The release/high and output/low
control matching open-drain states also reproduces corruption with the BSC
idle. Readback, unchanged pin-mode rewrites, and direction changes that keep
READY high pass the finite controls.

The connected/disconnected/reconnected comparison implicates the connected
READY path. The fixed-output high/low control fails after eight successful
echoes with the lead connected; disconnecting only the lead at controller
GPIO22 passes all 500 echoes (1,449,901 payload bytes over 7,153 GPIO cycles).
Reconnecting the same lead restores request-write `EREMOTEIO` after 67 successful
echoes and 674 GPIO cycles. Electrical checks verify both wiring states. The
failing request waits 11 microseconds for the bus lock. The idle peer's BSC
transaction and byte counters remain zero during the two physical controls.

Follow-up controls retain the same GPIO17 high/low pulse workload:

| READY path / controller input | Successful echoes before failure | Failure |
|---|---:|---|
| Breadboard, GPIO22, C3 tip disconnected | 85 | Request-write `EAGAIN`, lost arbitration |
| Direct jumper, GPIO22, C3 tip disconnected | 13 | Response-payload `EAGAIN`, lost arbitration |
| Direct jumper, GPIO24, C3 tip disconnected | 43 | Request-write `EREMOTEIO` |
| Direct jumper, GPIO24, repeated for scope | 11 | Full-length 3,136-byte reply differs at byte 915 |

A 100-echo baseline without pulses passes after bus recovery and again with
GPIO24 connected. The idle peer's transaction/byte counters remain zero.
GPIO22 specifically, READY breadboard contacts and C3's tip are therefore not
required for this finite reproduction. Other scope/ground paths, wire loading,
shared controller effects and target output/ground coupling remain unresolved.
The I2C diagnostic sources and loaded target module match the earlier controls;
other dependency/binary changes limit direct comparisons across the lab reboot.

Lost arbitration can leave SDA low. The affected target service was restarted
with the same profile, binary and state path; low/release recovery clocks and a
STOP restored bus idle, followed by the passing baseline. No uncertain HSM
mutation was replayed. The latest scope-assisted run confirmed Stop, but the
export contains a subsequent device-info exchange rather than the corrupt
reply. No new time-aligned failure waveform is claimed.

Diagnostic wiring currently connects Pi2 GPIO17 (pin 11) directly to controller
GPIO24 (pin 18), with C3 disconnected. The documented normal bench mapping is GPIO22;
no production configuration was changed. Any subsequent two-target diagnostic must use
GPIO24 explicitly or restore the physical GPIO22 connection first. Diagnostic
jobs are stopped. The next measurement should correlate the actual failure
with SDA/SCL while controlling READY loading and ground return.

See the target [READY isolation record](https://github.com/qpernil/raspberry-pi-i2c-target/blob/main/docs/ready-signal-isolation.json)
for counts, source revisions and limits. Concurrent authenticated PQC remains
unqualified; no firmware or lock-policy change was made for these controls.

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
of all existing objects. The fair-acquisition validation restores the current
99/21-object inventories. The earlier [qualification record](i2c-pqc-qualification.json)
retains the original 56/17-object snapshots, construction coverage and transport
failure evidence; those snapshots are historical test baselines.

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

### Controller-local connector echo diagnostics

Run `tools/i2c-connector-stress.py` on the controller with a loopback connector
URL so an SSH forwarding interruption cannot be mistaken for an I2C failure.
The tool sends only unauthenticated, non-mutating echo commands and compares
complete response frames. It does not create sessions, discover USB hardware,
or change HSM objects. Use a temporary connector with explicit I2C endpoints
and hardware discovery disabled; no other process may own those READY lines.
For the documented bench topology:

```sh
target/release/pkcs11rs-connector --listen 127.0.0.1:22346 \
  --hardware-discovery false --serials 24000001,25000002 \
  --i2c-yubihsm /dev/i2c-1@0x24=/dev/gpiochip0:23 \
  --i2c-yubihsm /dev/i2c-1@0x25=/dev/gpiochip0:22
```

From another controller terminal, with access to the same checkout:

```sh
python3 tools/i2c-connector-stress.py --serials 24000001 25000002 \
  --count 1000 --output /tmp/i2c-connector-evidence
```

The evidence directory must not exist. It contains per-request JSONL records,
a run configuration, and the final result. The first HTTP error, timeout or
byte mismatch stops new requests to both targets, records the attempted
request, and retains the expected and available actual echo response. In-flight
requests may finish before the tool exits. Requests are never retried. Use the
recorded seed and per-request index to reproduce the generated echo bytes.

An optional `--scope-host ADDRESS` stops a preconfigured Siglent acquisition
on the first failure and verifies the returned `Stop` status. It preserves an
already stopped acquisition and never forces or rearms a replacement record.
The evidence includes command timing, status history and any capture error.
Configure SCL/SDA/READY channels and a suitable acquisition window before
the run; this option does not configure or retrieve waveforms. A timeout can be
reported after the initiating wire event has left a short acquisition window.
Scope-command failure is recorded separately from the transport failure.

Stop the temporary connector after the run and verify release of the bus and
READY lines. Retain target counter snapshots before and after the experiment.
Finite echo success does not qualify concurrent authenticated/PQC workloads.
The HTTP success, mismatch, error and timeout evidence paths are exercised with:

```sh
python3 -m unittest discover -s tools -p test_i2c_connector_stress.py -v
```

### Exchange phase timing

Enable `RUST_LOG=pkcs11rs_connector::i2c::timing=debug` on a diagnostic connector
to record one metadata-only timing entry per attempted exchange. Each entry
identifies the bus, address, exchange ID, request/response lengths, result and
last phase. It separates request-lock wait, request setup, request write,
cleanup acknowledgment, response READY wait, response-lock wait, response setup,
header read and body read, in microseconds. Read phases include their adjacent
validation/allocation work. Response length is recorded for completed frames.
Errors retain elapsed time through the failed phase. Entries are emitted after
the bus locks are released; command bytes, credentials and session keys are not
logged. Timing is disabled at ordinary log levels. Lock scope, retry policy and
exchange deadlines are unchanged.

`tools/i2c-authenticated-probe.c` is a macOS lab client using the existing Secure
Enclave `reserve` credential and target Authentication Key `1003`. Its `read`
mode repeatedly invokes `C_GetSessionInfo`, which performs an authenticated
GetStorageInfo request rather than reading a cached public key. Its `sign` mode
requires an explicitly selected existing RSA private signing key and signs a
domain-labelled test message. It checks the response length; it does not
cryptographically verify signatures or require separate public-key objects.
`inventory` reports public object identity/attributes for before/after comparison.
The client has no key creation, import, modification or deletion mode, disables
local hardware
discovery and transparent session recreation, and stops on the first error.
Run read and signing roles in separate processes so PKCS #11 context locking
does not serialize their traffic. The optional shared start barrier makes both
authenticated sessions ready before measurements begin.

Build it against this checkout's headers and run it in a signed host with the
existing platform-credential access group, as described in the qualification
record. It accepts the module path, connector URL, serial, mode, operation count,
optional RSA key ID as hex bytes, and optional barrier directory. No password is
accepted or retained. Select only keys already present in the baseline inventory;
compare inventories afterward. The credential stays on the Mac, so this client
is distinct from the controller-local unauthenticated echo diagnostic.
