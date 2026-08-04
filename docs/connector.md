# PKCS11RS multi-device connector

`pkcs11rs-connector` is an asynchronous network gateway for all YubiHSMs
attached to one host over USB. It is built in the same Cargo workspace as the
PKCS #11 module but is a separate package, so its Tokio, Axum, server-side TLS,
and asynchronous nusb dependencies never enter the iOS XCFramework.

> **Security status:** the connector is suitable for loopback, a trusted
> private network, or access through a tightly controlled VPN or reverse proxy.
> It is not yet hardened or approved for direct exposure to the public
> Internet. HTTPS and mTLS are implemented, but transport encryption alone
> does not supply the authorization, admission control, recovery, and
> operational hardening listed in
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

Device detachment removes the corresponding entry. A request already holding
the entry completes with a transport error if the USB transfer fails; a newly
attached device receives a new entry even when it has the same serial. Duplicate
simultaneously attached serials are rejected rather than routed ambiguously.

Opening and claiming a device currently happens only during initial discovery
or a hot-plug event. A failed open or claim is not retried while the device
remains attached, a failed command does not proactively reopen its USB handle,
and an ended hot-plug stream is reported but not restarted. These are known
recovery limitations rather than guarantees that an entry remains usable for
as long as it remains in the registry.

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
    }
  ]
}
```

`GET /v1/devices/{serial}` returns one entry or `404 Not Found`.

PKCS11RS consumes this API exclusively for remote YubiHSM access. One
configured connector URL is discovered into one PKCS #11 slot per returned
serial, and every slot sends commands only to its serial-specific endpoint.

### Execute a command

```http
POST /v1/devices/{serial}/commands
Content-Type: application/octet-stream
```

The body is one complete native YubiHSM command frame. A successful transport
returns the native response frame as `application/octet-stream`, including
ordinary device-level error frames. Transport failures use a structured JSON
HTTP error.

The current HTTP body limit rejects inputs larger than 3,139 bytes, matching
the broad limit accepted by Yubico's connector protocol. It does not yet
require the three-byte frame header, compare the embedded big-endian payload
length with the actual body, or apply the firmware-specific USB frame limit.
Until the validation item below is implemented, only clients that already
produce valid YubiHSM frames should be allowed to reach the command endpoints.
The shared USB boundary must ultimately enforce a maximum total frame size of
2,048 bytes before firmware 2.4 and 3,136 bytes for firmware 2.4 and later.

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
2. Without configuration, exactly one attached device is selected.
3. Zero devices report `NO_DEVICE`.
4. Multiple devices report `MULTIPLE_DEVICES`; the connector never selects the
   first enumerated device.

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

- Validate every request as exactly one YubiHSM frame before acquiring the
  device gate: require at least three bytes, decode the big-endian payload
  length, and require `body length == 3 + declared length`.
- Enforce the firmware-specific total USB frame maximum at the shared hardware
  boundary: 2,048 bytes before firmware 2.4 and 3,136 bytes for firmware 2.4
  and later. Apply the same rule to blocking local access and asynchronous
  connector access so an HTTP bypass cannot reach older hardware.
- After a USB transport failure, return the failure without replaying the
  command, discard the uncertain handle, and reopen it for a subsequent
  request. Automatic replay is unsafe because a mutating command may already
  have executed.
- Periodically reconcile enumeration with the registry, retry transient open
  and claim failures with bounded backoff, and recover or terminate if the
  hot-plug event stream ends.
- Make status reflect an actively usable device handle rather than registry
  presence alone.

### Resource and denial-of-service controls

- Add header-read, body-read, complete-request, write, and idle deadlines. The
  USB command timeout begins only after a request obtains its device gate and
  does not currently bound time spent waiting in front of that gate.
- Bound accepted connections, simultaneous HTTP requests, HTTP/2 streams, and
  total in-flight command work.
- Replace the unbounded per-device mutex wait with bounded admission and a
  short queue deadline. Return `429 Too Many Requests` or `503 Service
  Unavailable` when capacity is exhausted.
- Apply global and authenticated-client rate limits so many requests cannot
  accumulate behind one slow HSM or across all attached HSMs.

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
--tls-certificate PATH
--tls-key PATH
--tls-client-ca PATH
--allow-insecure-http
```

Set `RUST_LOG` to control structured diagnostics, for example:

```sh
RUST_LOG=pkcs11rs_connector=debug cargo run -p pkcs11rs-connector
```
