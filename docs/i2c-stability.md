# Experimental I2C HSM transport requirements and validation

The Linux I2C YubiHSM transport is intended for niche hardware experiments.
It requires the connector's `experimental-i2c` build feature and explicit
endpoint configuration. The single-flight request/response protocol runs
between a controller using `i2c-dev` and a Raspberry Pi BSC target. A compatible
deployment uses the `raspberry-pi-i2c-target` driver ABI 3 with its READY request handshake and the controller implementation in
`pkcs11rs-connector/src/i2c/`. PKCS #11 applications and the qualification
tool access I2C HSMs through the connector's HTTP API.

## Oscilloscope experiments

This is a companion to the Raspberry Pi display-bus experiments described in
the [Virtual Trezor I2C display plan](https://github.com/qpernil/virtual-trezor/blob/main/docs/i2c-display-plan.md),
which uses a Siglent SDS824X HD to observe SCL, SDA, and timing markers. The
HSM experiment adds request/response traffic and READY signaling to
that bench setup. Capture SCL and SDA together with READY to
inspect response latency, header/body pauses, and response completion.

Record the measured SCL rate separately from the configured adapter rate; the
display plan documents the Pi 4 clock-scaling discrepancy found with the scope.
Follow the target driver's
[hardware and oscilloscope validation plan](https://github.com/qpernil/raspberry-pi-i2c-target/blob/main/docs/hardware-test-plan.md)
for wiring, signal-integrity checks, and evidence to retain. These experiments
provide lab evidence for a particular setup, not general electrical qualification.

## Exchange contract

Use driver ABI 3 with READY configured on both ends. The controller holds the
bus lock through request writing and the target's cleanup acknowledgment
(physical rising READY edge), releases the bus during computation, then
reacquires it to read the three-byte header and exact-length body. READY stays
asserted after reading; a new request clears previous transmit state. The
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
abandoned last bytes and superseded worker results. The Linux connector passes
34 unit tests and Clippy with warnings denied; its Mac suite passes 33 tests.
The frontend passes Linux target checking, and both Pis build the kernel module.

Both targets pass 1,000 simultaneous randomized exchanges each (about 1.55 MB
of declared payload per target), with a 5 ms header/body gap and every tenth
response left one byte unread. The run includes bounded four-core CPU load.
Neither target reports an overrun or underrun.

A hardware recovery probe delays one worker write by two seconds, then sends
two replacement requests. Only the newest response is returned. The driver
records one replaced pending request and one discarded stale worker result.
Reproduce with `--supersede-every 1` and a response-write delay injected on the
target; the test uses synthetic echo data and does not require authentication.

All 31 supported `yubihsm-shell` cases pass against each HSM (77.80 s and
95.33 s), while the other HSM answers continuous byte-exact HTTP echo requests.
The unsupported SSH-template and wrapped-object cases remain excluded.
During Pi 1's suite, Pi 2 serves 5,387 echoes with 2.67 ms median and 79.19 ms
maximum latency across the 180-second measurement window. An isolated reverse
RSA check serves 763 Pi 1 echoes with 2.64 ms median and 15.03 ms maximum
latency across 25 seconds. HTTP smoke, managed and extension qualification
also pass on both targets.

The topology is ubuntu4 controlling raspberrypi-1 (`0x24`, serial 24000001,
READY GPIO23) and raspberrypi-2 (`0x25`, serial 25000002, READY GPIO22).
Targets use GPIO17 for READY and separate qualification state directories.

## Reproduction

Stop the connector before the raw tool claims its READY lines:

```sh
python3 tools/i2c-stress.py 0x24 --ready /dev/gpiochip0:23 --count 1000 --payload-gap-ms 5
python3 tools/i2c-stress.py 0x25 --ready /dev/gpiochip0:22 --count 1000 --abandon-every 10
```
