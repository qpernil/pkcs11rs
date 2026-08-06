# PKCS11RS multi-device connector

`pkcs11rs-connector` is an asynchronous network gateway for all YubiHSMs
attached to one host over USB. It is built in the same Cargo workspace as the
PKCS #11 module but is a separate package, so its Tokio, Axum, server-side TLS,
and asynchronous nusb dependencies never enter the iOS XCFramework.

> **Security status:** the connector is suitable for loopback, a trusted
> private network, or access through a tightly controlled VPN or reverse proxy.
> It is not approved for direct exposure to the public Internet. HTTPS, mTLS,
> bounded HTTP admission, YubiHSM frame validation, firmware-aware USB limits,
> transport timeouts, hot-plug handling, and recovery after system suspend are
> implemented. Device-aware authorization, connection and client rate limits,
> and the remaining operational controls are listed in
> [Internet-readiness work](#internet-readiness-work).

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
Only devices successfully opened and claimed appear in the registry and
`/v1/devices`; physical attachment alone is not connector presence.

The connector detects a delayed timer tick caused by system suspend. After
resume it stops the old HTTP service, discards surviving connections, the USB
discovery watcher, registry, mutexes, and device handles, and rebuilds them in
the same process. An implicitly selected legacy serial is carried into the new
service, so this recovery does not change the selected compatibility device.
The complete set of serials successfully claimed before suspend is also
carried into the rebuilt service. Initial enumeration after resume reclaims
only that set, preventing the connector from taking ownership of a device that
another application was already using. A full process restart forgets this
ownership set and starts a new implicit legacy selection unless
`--legacy-serial` is configured. A fresh hot-plug event after the rebuild is
handled normally and may add a newly attached device.

Opening and claiming a device currently happens during initial discovery, a
hot-plug event, or reclamation of a previously managed serial after system
resume. A failed initial open or claim is logged, omitted from the advertised
inventory, and intentionally not retried while the device remains attached;
the device may belong to another local application. A failed command does not
proactively reopen its USB handle.

### Verified suspend and ownership recovery

The suspend detector checks wall-clock progress every two seconds and rebuilds
the service when a timer gap is greater than twelve seconds. It therefore
detects real system suspension, not merely display sleep or screen locking. For
a manual test, allow the Mac to enter actual system sleep before measuring the
sleep interval; one minute is a convenient reliable duration.

The ownership behavior has been verified on macOS with physical YubiHSMs:

1. `yubihsm-shell` claimed one HSM through local USB before the connector
   started.
2. The connector left that HSM unmanaged while managing the other available
   HSM.
3. `yubihsm-shell` was stopped, making its HSM claimable without generating a
   physical hot-plug event.
4. After a real Mac sleep and resume, the connector rebuilt its HTTP and USB
   services and reclaimed only the serial it had managed before sleep. It did
   not take ownership of the now-claimable, previously unmanaged HSM.
5. Removing the unmanaged HSM produced no connector detach log, because it had
   no registry entry. Physically reconnecting it generated a new hot-plug event
   and allowed the connector to claim and advertise it normally.

This test covers the distinction between service reconstruction, release of a
device by another process, and a genuine new physical attachment. The expected
inventory can be checked before and after sleep with `GET /v1/devices`.

The shared `pkcs11rs-local-hardware` crate exposes both blocking and async
frontends. The existing PKCS #11 local connector continues to use the blocking
frontend and contains no Tokio runtime. This daemon enables the `async-tokio`
frontend. Portable and iOS builds omit the shared hardware crate entirely.

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
alone until it is physically detached and reattached; enumeration and resume
do not retry the claim. Clients create slots only for `available` devices and
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
timeout.

## Legacy protocol

The compatibility endpoints are:

```text
GET  /connector/status
POST /connector/api
```

Selection follows these rules:

1. `--legacy-serial SERIAL` always selects that serial or reports it absent.
2. Without configuration, the serial of the first successfully discovered
   device is latched for the connector process lifetime, including internal
   service rebuilds after system suspend.
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

The default `info` level records listener state, device attachment and
detachment by serial and transient USB device ID, and suspend recovery. Enable
request diagnostics with:

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

### Protocol and USB safety

- After a USB transport failure, return the failure without replaying the
  command, discard the uncertain handle, and reopen it for a subsequent
  request. Automatic replay is unsafe because a mutating command may already
  have executed.

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
- Handle both Ctrl-C and service-manager termination signals with bounded
  graceful shutdown.
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
