# Experimental I2C HSM transport requirements and validation

Hostnames and device/account identifiers below are illustrative; replace them with your own configured values.

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

Use target character-device ABI 3 with READY and the explicit recovery capability.
[The exchange contract](https://github.com/qpernil/raspberry-pi-i2c-target/blob/main/docs/response-transport.md)
keeps ordinary application requests and responses unchanged, including the
8192-byte limits. There is no additional request envelope or CRC. Normal exchanges
keep BSC enabled in I2C mode. The bus lock covers the request and its rising READY
acceptance edge, and separately the exact header/body response read.

READY detection stays rising-only for the connection. Response readiness uses
100 microsecond level-poll intervals, subject to Linux scheduling. The existing
`cleanup_ack` timing metric measures request acceptance, not a normal purge.

Before DeviceInfo on open/reconnect, the connector sends the reserved frontend
control frame `00 00 0d BSCRECOV 01 TOKEN32`, using existing HSM framing. The I2C
frontend invokes `BSC_TARGET_IOC_RECOVER` and confirms the token with response
command `80`. This control is outside the HSM core. The bus lock covers the whole
recovery exchange. Any incomplete exchange closes the transport; reopening
recovers before another command. An uncertain command is never replayed.

Adapter errors, HSM frame validation and authenticated-session MACs supply their
existing error checks. A raw unauthenticated protocol without integrity cannot
detect all silent bit corruption. Recovery does not clear a physically stuck bus.
Generic driver clients retain their normal byte protocols; abandoning a reply
requires an application-specific recovery operation or a quiescent target restart.
The HSM frontend, connector and recovery-capable driver must be updated together.

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


## Validation

The target C model verifies raw byte delivery, normal exchanges without resets,
and explicit abandoned-response recovery. Updated hardware qualification is
recorded in the [driver validation record](https://github.com/qpernil/raspberry-pi-i2c-target/blob/main/docs/explicit-recovery-validation.json).
The READY2-triggered fault remains unqualified and must be checked with READY2,
SDA and SCL captured together.

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

The hardware topology is build-host (Pi 5/RP1) controlling i2c-target-1 (`0x24`,
serial 24000001, READY GPIO23) and i2c-target-2 (`0x25`, serial 25000002,
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

A byte-correlated capture uses hardware single acquisition, triggered on an
I2C write to address `0x24` with first data byte `0x01` (echo). Each arm sends
one 3,133-byte echo, preventing later device-info traffic from replacing the
record. The clean capture matches the complete saved request and response body.
With READY pulsing, five echoes pass and the sixth fails with request-write
`EAGAIN` and kernel lost arbitration. Its scope record matches the first 2,604
saved request bytes. The next byte (zero-based request offset 2,604) should be
`0x9D`; the wire presents eight data bits `0x9C`, then clocks stop before ACK.
SDA remains low while SCL stays high. A native 20 ns excerpt preserves that bit.

This establishes the actual on-wire failure, but not which device holds SDA
low or why. C3 remains disconnected, so no READY-edge timing is available;
receiver thresholds and probe skew are uncalibrated. Recovery with low/release
clocks and STOP restores idle-high lines; four no-pulse echoes then pass.
The failed acquisition remains stopped and no uncertain HSM mutation is replayed.

A post-abort output-isolation control identifies the addressed target as the
held-low source. After a 4,668-byte echo write loses arbitration, disconnecting
only idle Pi2's GPIO18 SDA output (input mode) leaves SDA low. Restoring Pi2
ALT3 leaves it low. Disconnecting only addressed Pi1's SDA output raises SDA;
restoring Pi1 ALT3 pulls it low again. No clocks, READY configuration changes,
service restarts or physical rewiring occur during those checks. Pi1 then
reports `FR=0x32` (`RXBUSY=1`, `TXBUSY=0`); idle Pi2 reports `FR=0x12`.

The BSC hardware generates receiver ACKs, so receive-busy does not imply a
high-impedance SDA output. These observations fit a receive/ACK state waiting for another clock.
They identify the post-abort holder, not the cause of the original bad bit or
whether a driver transition or hardware misalignment initiated it. Recovery
clocks and STOP restore the bus; four subsequent echoes pass and both flag
registers return to `0x12`. Both SDA muxes are restored; original services
remain running.

The separate NACK capture's roughly 23 microsecond READY pulse is the intended
cleanup acknowledgement. Its first cleanup rise overlaps the following
`0x06` device-info write by about 40 microseconds after that write starts.
The target logs record the partial echo and complete device-info request;
this recovery overlap remains distinct from the original arbitration loss.

Diagnostic wiring currently connects Pi2 GPIO17 (pin 11) directly to controller
GPIO24 (pin 18), with C3 disconnected. The documented normal bench mapping is GPIO22;
no production configuration was changed. Any subsequent two-target diagnostic must use
GPIO24 explicitly or restore the physical GPIO22 connection first. Diagnostic
jobs are stopped. The next measurement should trace receive completion and
BSC reconfiguration against wire timing to distinguish driver transitions from
hardware loss of alignment.

See the target [SDA output isolation](https://github.com/qpernil/raspberry-pi-i2c-target/blob/main/docs/sda-output-isolation.json),
[correlated failure capture](https://github.com/qpernil/raspberry-pi-i2c-target/blob/main/docs/ready-failure-capture.json)
and [READY isolation record](https://github.com/qpernil/raspberry-pi-i2c-target/blob/main/docs/ready-signal-isolation.json)
for counts, source revisions and limits. Concurrent authenticated PQC remains
unqualified; no firmware or lock-policy change was made for these controls.

## PQC provider qualification

The deployed `pqc_matrix_deployed_yubihsm` suite passes single-target baselines
on both I2C targets through build-host's connector. Concurrent shared-bus operation
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
