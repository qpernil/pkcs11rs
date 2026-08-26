# PKCS11RS multi-device connector

`pkcs11rs-connector` is an asynchronous network gateway for all YubiHSMs
attached to one host over USB. It is built in the same Cargo workspace as the
PKCS #11 module but is a separate package, so its Tokio, Axum, server-side TLS,
and asynchronous nusb dependencies never enter the iOS XCFramework.

> **Security status:** the connector is suitable for loopback, a trusted
> private network, or access through a tightly controlled VPN or reverse proxy.
> It is not approved for direct exposure to the public Internet. HTTPS, mTLS,
> bounded HTTP admission, YubiHSM frame validation, firmware-aware USB limits,
> transport timeouts, hot-plug handling, and continuity across system suspend
> are implemented. Device-aware authorization, connection and client rate
> limits, and the remaining operational controls are listed in
> [Internet-readiness work](#internet-readiness-work).

## Embedded virtual YubiHSMs

On Unix, the connector can compile `virtual-yubihsm-core` directly into the
process. Build the release binary with:

```sh
cargo build --release -p pkcs11rs-connector \
  --features embedded-virtual-yubihsm
```

Each `--virtual-yubihsm SERIAL=STATE_DIRECTORY` argument adds one independent
device. For example, this starts two virtual devices and deliberately disables
physical USB discovery:

```sh
target/release/pkcs11rs-connector \
  --hardware-discovery false \
  --virtual-yubihsm 12345678=/var/lib/pkcs11rs/yubihsm-12345678 \
  --virtual-yubihsm 87654321=/var/lib/pkcs11rs/yubihsm-87654321
```

Serial numbers and absolute state directories must be unique. A missing state
directory is created with mode `0700`; a missing state file is initialized as
a factory-default YubiHSM. The state filename is `yubihsm-SERIAL.cbor`, with a
persistent `yubihsm-SERIAL.lock` sidecar preventing simultaneous connector and
USB-worker ownership. Do not point two configured processes at the same state
file.

The same arguments can be retained when switching binaries by recompilation:

| Connector build | Virtual-device arguments | `--hardware-discovery false` |
| --- | --- | --- |
| Feature enabled | Start the configured devices | Disables physical discovery |
| Feature absent | Accepted and ignored with a warning | Accepted and ignored; physical discovery remains enabled |

Mutating commands are persisted in receipt order. The default `batched` policy
coalesces mutations for at most 500 ms; use
`--virtual-yubihsm-persistence immediate` when every successful mutation must
wait for durable storage. The batch bound can be changed with
`--virtual-yubihsm-batch-delay-ms MILLISECONDS`.

## Architecture

The connector starts the nusb hot-plug watch before its initial enumeration,
then maintains two indexes:

```text
USB device ID -> serial number -> device entry
```

Each device entry owns an asynchronous access gate and its opened nusb device.
The gate is held from command submission through USB response completion. This
means concurrent HTTP requests for one serial block without executing
concurrently, while separate physical HSMs remain independent.

An optional Unix-only `embedded-virtual-yubihsm` build feature adds headless
virtual devices to the same registry. Each embedded device owns a dedicated OS
thread running `virtual-yubihsm-core`. The asynchronous transport sends one
request through a capacity-one Tokio MPSC channel and awaits its result through
a one-shot channel. Synchronous cryptography, state locking, and file syncing
therefore never block a Tokio runtime worker. A received mutation is completed
and accounted for even if its HTTP requester is cancelled before receiving the
reply.

Configure an instance by repeating
`--virtual-yubihsm SERIAL=STATE_DIRECTORY`. Embedded instances use distinct
absolute state directories and serials. The common persistence policy is
selected with `--virtual-yubihsm-persistence batched|immediate`; batching uses
a 500 ms maximum delay unless changed with
`--virtual-yubihsm-batch-delay-ms`. The actor acquires the same persistent
sidecar lock as the USB worker before restoring state and releases it only
after graceful persistence shutdown. This allows the same virtual device state
to move between connector and USB frontends across separate runs, but forbids
simultaneous ownership.

All virtual-HSM command, crypto, and durable-state dependencies are optional.
A connector compiled without the feature still parses these options, logs that
configured virtual instances are ignored, and continues as a physical-only
connector. It also accepts but ignores `--hardware-discovery false`, retaining
normal hardware discovery so an embedded-oriented configuration can safely be
used by a featureless binary.

Virtual instances are always opt-in. In an embedded-enabled build, local USB
discovery remains enabled by default but can be disabled independently with
`--hardware-discovery false`. Consequently that build can expose only physical
devices, only configured virtual devices, both inventories together, or no
devices while retaining a live connector endpoint. A featureless build always
discovers physical devices.

The per-device gate deliberately has no queue timeout: accepted requests wait
until preceding commands for that device finish. A global Tower concurrency
limit bounds the number of requests in all device queues and handlers. The
default is 64 requests and can be changed with
`--http-max-in-flight-requests`; excess requests are rejected immediately with
`503 Service Unavailable` without making an existing HTTP connection unusable.

Device detachment removes the corresponding entry. A request already holding
the entry completes with a transport error if the USB transfer fails; a newly
attached device receives a new entry even when it has the same serial. Duplicate
simultaneously attached serials are rejected rather than routed ambiguously.
Every identifiable device appears in `/v1/devices`; devices the connector
successfully claimed are `available`, while devices owned elsewhere are
`unclaimed`.

System suspend pauses the process but does not trigger connector
reconstruction. The HTTP listener, accepted connections, USB discovery
watcher, registry, and claimed device handles remain in place. Requests made
while the host or its network interface is unavailable can time out, but new
requests are accepted after network recovery without rebinding the listener.
Sleep/wake does not rescan USB or retry an initially failed claim. Ordinary
physical detach and attach events continue to update the registry.

Ctrl-C (`SIGINT`) and the Unix service-manager termination signal (`SIGTERM`)
both initiate the same bounded graceful HTTP shutdown before discovery and USB
state are released. This allows service managers such as systemd to use their
normal termination behavior without a connector-specific kill-signal override.

Opening and claiming a device happens during initial discovery or a hot-plug
event. A failed initial open or claim is logged as `unclaimed` and intentionally
not retried while the device remains attached; it may belong to another local
application. An actual USB transport failure returns without replaying the
possibly executed command and discards the uncertain handle. The next request
for that device enumerates the same transient USB ID, verifies its serial,
opens a fresh handle, and claims the interface before submitting its command.
Reopening remains inside the per-device gate, so it cannot race another command
for that HSM. A malformed or oversized frame rejected before USB submission
does not invalidate a healthy handle.

### Verified sleep/wake behavior

A USB-only test retained one claimed YubiHSM handle across 121.7 seconds of
real macOS sleep. Immediately after wake, a cleartext `DeviceInfo` command
through the original handle completed in under one millisecond. Enumeration
while retaining that claim took two milliseconds. Releasing the original and
performing a complete enumerate, open, claim, and `DeviceInfo` sequence also
completed successfully, with each phase taking at most two milliseconds. This
supports retaining USB state rather than rebuilding it after every delayed
timer tick. A longer overnight sleep remains a useful deeper-power-state test.

Ownership behavior has also been verified with two physical YubiHSMs:

1. `yubihsm-shell` claimed one HSM through local USB before the connector
   started.
2. The connector left that HSM unmanaged while managing the other available
   HSM.
3. `yubihsm-shell` was stopped, making its HSM claimable without generating a
   physical hot-plug event. It remained `unclaimed` because the connector does
   not rescan or retry claims while a device stays attached.
4. Physically reconnecting it generated a new hot-plug event and allowed the
   connector to claim and advertise it as `available`.

YubiHSM secure sessions are separate from USB transport state. The device
expires a secure session after 30 seconds without a session command and then
returns error `0x03` (`invalid session`). Real sleep cannot be bridged by a
host keepalive. By default, a logged-in client therefore discards the expired
session and becomes logged out after a sufficiently long sleep. The optional
`yubihsm.recreate_sessions` setting authenticates again and replays one command
only after the explicit invalid-session response; retaining the HTTP and USB
transports alone does not retain an expired secure session. See Yubico's
[Session documentation](https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-intro-core-concepts.html#session).

### USB-only sleep/wake test

The separate `yubihsm-usb-resume-test` binary isolates the YubiHSM USB path
from HTTP, networking, PKCS #11, and secure sessions. Stop the connector and
any other process using the selected YubiHSM, then run:

```sh
cargo run -p pkcs11rs-connector --release \
  --bin yubihsm-usb-resume-test -- --serial 12345678
```

After a successful baseline command, put the Mac into real system sleep. The
test detects a delayed wall-clock tick. Immediately after wake it sends the
unauthenticated cleartext YubiHSM `DeviceInfo` command
through the original claimed handle, tests fresh enumeration while retaining
that handle, releases it, and repeats enumeration, open, claim, and
`DeviceInfo` through a fresh handle. Every phase reports its duration and
outcome. The test is read-only and does not create, use, or close a YubiHSM
secure session; session continuity can therefore be tested separately after
the underlying USB behavior is known.

### HTTP listener sleep/wake test

The separate `http-resume-test` binary isolates the connector's HTTP server
stack from USB and the YubiHSM protocol. It retains one HTTP/1.1 connection
across real system sleep and, immediately after wake, tests that connection in
parallel with a new TCP connection and HTTP request. The fresh connection is
the direct test of whether the preserved listener still accepts after wake.

Run it on a port separate from the connector, then sleep the Mac when prompted:

```sh
cargo run -p pkcs11rs-connector --release \
  --bin http-resume-test
```

The default listener is `0.0.0.0:12346`, while the automated probes connect
through `127.0.0.1`. A usable fresh connection proves local listener and accept
behavior; it does not prove that a LAN interface is externally reachable. To
test that remaining path from another computer, request the real connector
with a new cache-busting value after wake:

```text
http://192.168.1.90:12345/v1/devices?probe=1
```

A newly started command-line HTTP client with `Connection: close` gives the
strongest fresh-connection test. If localhost succeeds immediately while the
remote request remains delayed, the failure is between the LAN interface and
the remote client.

On macOS, this test has been verified across 70.0 seconds of real sleep. The
pre-sleep HTTP/1.1 connection had been closed, while a fresh TCP connection was
accepted and served in one millisecond immediately after wake. Closure of the
idle connection is informational: the server's five-second HTTP/1 header-read
deadline is allowed to close it. The successful fresh request is the relevant
listener and accept result.

PKCS11RS uses one pooled `ureq` agent for each configured connector entry.
Inventory refreshes and every slot returned for that entry reuse the agent
while it remains healthy. Concurrent requests may open separate TCP
connections from its pool; they are not serialized onto one HTTP/1.1
connection. A transport failure clears the shared agent and pool for that
connector entry. The next caller-initiated inventory refresh then starts with
a fresh agent; the client does not retry internally. Even identical configured
URL strings remain independent connector entries with independent pools.

The shared `pkcs11rs-local-hardware` crate exposes both blocking and async
frontends. The existing PKCS #11 local connector continues to use the blocking
frontend and contains no Tokio runtime. This daemon enables the `async-tokio`
frontend. Portable and iOS builds omit the shared hardware crate entirely. An
iOS build instead discovers and uses local CCID readers directly through
CryptoTokenKit.

## Multi-device API

### Enumerate devices

```http
GET /v1/devices
```

```json
{
  "devices": [
    {
      "serial": "12345678",
      "manufacturer": "Yubico",
      "product": "YubiHSM",
      "usb_version": "2.5",
      "status": "available"
    },
    {
      "serial": "87654321",
      "manufacturer": "Yubico",
      "product": "YubiHSM",
      "usb_version": "2.5",
      "status": "unclaimed"
    }
  ]
}
```

The inventory contains every identifiable YubiHSM seen by USB enumeration.
`available` means that the connector owns the device interface and can execute
commands. `unclaimed` means that the device is physically present but was not
claimed by this connector, for example because another process owns it. This
makes the endpoint useful as remote USB inventory even when some attached
devices cannot be used through this connector. An unclaimed device is left
alone until it is physically detached and reattached; sleep/wake does not retry
the claim. Clients create slots only for `available` devices and
ignore all other, including unknown future, status values.

`GET /v1/devices/{serial}` returns one entry or `404 Not Found`.

PKCS11RS consumes this API exclusively for remote YubiHSM access. One
configured connector URL is discovered into one PKCS #11 slot per available
serial, and every slot sends commands only to its serial-specific endpoint.

### Execute a command

```http
POST /v1/devices/{serial}/commands
Content-Type: application/octet-stream
```

The body is one complete native YubiHSM command frame. A successful transport
returns the native response frame as `application/octet-stream`, including
ordinary device-level error frames. Transport failures use a structured JSON
HTTP error. A command addressed to an enumerated `unclaimed` device returns
`503 Service Unavailable` with error code `device_unclaimed`.

The HTTP middleware accepts request bodies up to 8,192 bytes. This deliberately
generic resource ceiling leaves room for a future firmware generation while
preventing an unbounded body from consuming connector memory. It does not
interpret YubiHSM framing before device selection or queueing.

After the selected device gate is acquired, the shared USB transport requires
the body to contain the command byte and two-byte big-endian payload length and
requires that declared length to match the remaining bytes exactly. It then
applies the firmware-specific total frame limit from that device's USB firmware
version: 2,048 bytes for firmware before 2.4 and 3,136 bytes for firmware 2.4
or any higher reported version. Future versions are thus treated like the
newest known firmware until support for a larger device frame is added. Both
checks run before endpoint access or bulk OUT submission. This protects
asynchronous HTTP and blocking local access from malformed frames and sizes
that can trigger hardware failures in some firmware versions.

The server never automatically retries a command. This is important for
non-idempotent operations whose outcome may be unknown after a transport
timeout. A transport failure invalidates the USB handle; a later request may
reopen the same identified device, but the failed command is never replayed.

## Legacy protocol

The compatibility endpoints are:

```text
GET  /connector/status
POST /connector/api
```

Selection follows these rules:

1. `--legacy-serial SERIAL` always selects that serial or reports it absent.
2. Without configuration, the serial of the first successfully discovered
   device is latched for the connector process lifetime.
3. The legacy routes then behave as if a client addressed that serial through
   `/v1/devices/{serial}` and `/v1/devices/{serial}/commands`.
4. Later attachments and changes to the device's transient USB identifier do
   not change the latched serial.
5. While that serial is absent, the endpoint reports `NO_DEVICE`; it does not
   fail over. If the same serial reappears after USB re-enumeration, it becomes
   available through the legacy endpoint again.

Restart the connector to choose a new implicit device, or use
`--legacy-serial` when the intended compatibility device is known.

The compatibility endpoint remains available to other legacy clients. Current
PKCS11RS versions use the multi-device API above instead.

A legacy client can use this endpoint with a single selected device. Its
status probe remains directly inspectable with:

```sh
curl http://127.0.0.1:12345/connector/status
```

## HTTP and HTTPS

The default listener is `127.0.0.1:12345`. Plain HTTP on a non-loopback address
is refused unless `--allow-insecure-http` is supplied explicitly.

Supplying a PEM server certificate chain and private key enables HTTPS:

```sh
pkcs11rs-connector \
  --listen 0.0.0.0:12345 \
  --tls-certificate /etc/pkcs11rs/server-chain.pem \
  --tls-key /etc/pkcs11rs/server-key.pem
```

Adding a client CA requires mutual TLS. Rustls rejects clients that do not
present a currently valid certificate chaining to one of these roots:

```sh
pkcs11rs-connector \
  --listen 0.0.0.0:12345 \
  --tls-certificate /etc/pkcs11rs/server-chain.pem \
  --tls-key /etc/pkcs11rs/server-key.pem \
  --tls-client-ca /etc/pkcs11rs/client-ca.pem
```

The TLS configuration supports TLS 1.3 and TLS 1.2 and advertises HTTP/2 and
HTTP/1.1 through ALPN. HTTPS without `--tls-client-ca` authenticates the server
to the client but permits any network client that can reach the listener to
submit requests. With a client CA, Rustls authenticates certificate chains,
but the application does not yet extract the verified identity or restrict it
to particular devices or commands. Every certificate accepted by that CA
therefore has the same access.

### Timeouts and admission

HTTP transport stages are bounded independently from HSM processing:

- TLS handshakes and HTTP/1 header reads have five-second deadlines.
- The complete request body has a five-second deadline and an 8,192-byte limit.
- HTTP/2 request header lists are limited to 16 KiB.
- A blocked response socket write has a five-second deadline; the timer runs
  only while a write is unable to make progress.
- At most 64 HTTP requests are processed concurrently by default. Use
  `--http-max-in-flight-requests` to change the limit. Excess requests receive
  `503 Service Unavailable` immediately.

There is no overall HTTP handler deadline. Once a complete request has entered
the command handler, it may wait indefinitely for its device gate. After it
obtains the gate, USB bulk writes have a fixed three-second timeout and the USB
response has the timeout selected by `--command-timeout-seconds`, which defaults
to 60 seconds. The response timeout does not include time spent waiting for the
device gate. Response headers are created only after the command result is
known, allowing the connector to return the correct final HTTP status.

These boundaries avoid racing a generic HTTP request timer against an active
USB command. The connector never automatically retries a command because a
mutating command may have executed even when its response is lost.

### Logging

The default `info` level records listener state and device attachment and
detachment by serial and transient USB device ID. Enable request diagnostics
with:

```sh
RUST_LOG=pkcs11rs_connector=debug pkcs11rs-connector
```

At `debug`, one completion event is emitted when each HTTP response has been
created. It includes the method, URI, HTTP version, status, and handler elapsed
time. Command responses also include the HSM serial, transient USB device ID,
transport outcome, and HSM command elapsed time. Failed commands also include a
stable `hsm_error_code` and descriptive `hsm_error`. Framing mismatches use
`invalid_command_frame`; frames above the selected firmware's limit use
`command_too_large` and report the actual size, permitted size, and firmware
version. The HSM time starts after the device gate is acquired, so the
difference from the handler time exposes queue waiting without producing a
second command log entry. Socket delivery occurs after this event and is
protected separately by the response-write timeout.

## Deployment boundary

The recommended current deployments are:

- loopback HTTP for a client on the connector host;
- HTTPS with mandatory mTLS on a firewalled private network;
- a private VPN such as WireGuard, with the connector reachable only through
  that network; or
- a hardened reverse proxy that supplies authentication, connection limits,
  deadlines, rate limiting, and an IP allowlist, while the connector remains
  bound to loopback or a private interface.

Do not publish the connector port directly on a public interface. Supplying a
server certificate without `--tls-client-ca` provides confidentiality but no
client authentication. YubiHSM secure sessions protect HSM command contents
and sensitive operations still require HSM credentials, but the connector
nevertheless grants access to the physical command transport. An unauthorized
caller can probe the device, consume its availability, and remotely exercise
any HSM credentials it obtains.

## Internet-readiness work

The following work remains before the connector should be considered suitable
for direct public-Internet exposure. A deployment may place equivalent controls
in a dedicated front proxy, but device-aware authorization and USB safety must
remain fail-closed in the connector itself.

### Resource and denial-of-service controls

- Bound accepted TCP connections before they reach the HTTP request middleware.
- Add authenticated-client and device-aware rate or admission limits so one
  identity cannot consume the global request capacity. The current global
  in-flight limit bounds total queued and executing work but does not provide
  fairness between clients or devices.
- Put public deployments behind infrastructure that supplies any additional
  HTTP/2 stream, idle-connection, and slow-header protection required by their
  threat model. Do not impose a generic complete-request deadline that can race
  an HSM command after USB execution has begun.

### Authentication and authorization

- Require HTTPS and mTLS for every non-loopback listener; an override intended
  for development must not silently weaken a production configuration.
- Propagate the verified certificate identity into request handling and map it
  explicitly to permitted device serials and, where required, command classes.
  Deny access when no policy matches.
- Support certificate revocation or deliberately short-lived client
  certificates, documented rotation, and fail-closed trust-store reloads.
- Allow discovery and the legacy protocol to be disabled independently. Do not
  expose device enumeration or compatibility routes unless clients need them.
- Require `application/octet-stream` on command endpoints and reject unexpected
  Host values where the listener can be reached through a browser or untrusted
  DNS. These checks reduce cross-origin and DNS-rebinding attack paths.

### Service and assurance

- Return stable public error codes without exposing raw USB or internal error
  strings. Record security audit events by authenticated identity, device
  serial, command code, result, and duration without recording command payloads
  or secrets.
- Run as a dedicated unprivileged account with access only to the required USB
  devices and TLS files. Combine this with firewall rules and operating-system
  service sandboxing.
- Continuously audit locked dependencies and test the HTTP and frame parsers
  with fuzzing, slow-client tests, load tests, malformed frames, USB removal,
  failed claims, transport timeouts, and hot-plug-stream failure injection.

Passing this checklist is separate from the HSM's own cryptographic security
and from ordinary unit-test or Clippy success. It requires a deployment threat
model and validation under the actual operating system, proxy, network, USB
controller, YubiHSM firmware, and certificate lifecycle used in production.

The frame checks are informed by Yubico's
[YSA-2021-02 denial-of-service advisory](https://www.yubico.com/support/security-advisories/ysa-2021-02/),
which documents how a frame shorter than three bytes can leave a connector
waiting indefinitely. Yubico's current client library separately applies the
[2,048-byte and 3,136-byte firmware limits](https://github.com/Yubico/yubihsm-shell/blob/master/lib/yubihsm.c),
while its connector applies only a broad
[HTTP request-size check](https://github.com/Yubico/yubihsm-connector/blob/master/api.go).
The shared hardware boundary should enforce both the structural and
firmware-specific rules even when an HTTP layer is bypassed.

## Operational options

```text
--listen ADDRESS
--legacy-serial SERIAL
--command-timeout-seconds SECONDS
--http-max-in-flight-requests COUNT
--tls-certificate PATH
--tls-key PATH
--tls-client-ca PATH
--allow-insecure-http
```

Set `RUST_LOG` to control structured diagnostics, for example:

```sh
RUST_LOG=pkcs11rs_connector=debug cargo run -p pkcs11rs-connector -- [OPTIONS]
```

## Running as a systemd service

Build the release binary on the target Raspberry Pi or another Linux host and
install it in a stable system path:

```sh
cargo build --locked --release -p pkcs11rs-connector
sudo install -m 0755 target/release/pkcs11rs-connector /usr/local/bin/
```

For example, create a dedicated unprivileged account:

```sh
sudo useradd --system --home /nonexistent --shell /usr/sbin/nologin \
  pkcs11rs-connector
```

Grant that account access to the YubiHSM USB
interface through the host's udev policy or a narrowly scoped device group.
Do not run the connector as root merely to obtain USB access. TLS private keys,
when used, should be readable by that account and no broader.

An example `/etc/systemd/system/pkcs11rs-connector.service` for loopback HTTP
is:

```ini
[Unit]
Description=PKCS11RS multi-device YubiHSM connector
After=network.target

[Service]
Type=simple
User=pkcs11rs-connector
Group=pkcs11rs-connector
ExecStart=/usr/local/bin/pkcs11rs-connector --listen 127.0.0.1:12345
Environment=RUST_LOG=pkcs11rs_connector=info
Restart=on-failure
RestartSec=2s
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true

[Install]
WantedBy=multi-user.target
```

Use the HTTPS and mTLS options documented above when the listener is reachable
from another host. Then load and enable the unit:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now pkcs11rs-connector
systemctl status pkcs11rs-connector
journalctl -u pkcs11rs-connector -f
```

systemd stops the service with `SIGTERM`, which follows the connector's bounded
graceful-shutdown path. `Restart=on-failure` restarts unexpected exits but not
an intentional `systemctl stop`.
