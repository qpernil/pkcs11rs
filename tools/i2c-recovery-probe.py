#!/usr/bin/env python3
"""Observe a fault and fresh-command recovery through an existing connector.

Only unauthenticated Echo commands are sent. No service is restarted, GPIO is
changed, bus is manually cleared, or failed command is replayed. This does not
qualify authenticated-session or PQC recovery.
"""
import argparse
import hashlib
import http.client
import importlib.util
import json
import math
import os
from pathlib import Path
import subprocess
import time
import types
from urllib.parse import urlsplit
import uuid


def save_json(path, value):
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def service_identity(name):
    if name is None:
        return None
    output = subprocess.check_output(
        ["systemctl", "show", name, "-p", "ActiveState", "-p", "MainPID",
         "-p", "InvocationID", "-p", "NRestarts",
         "-p", "ExecMainStartTimestampMonotonic"], text=True)
    identity = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
    if identity.get("ActiveState") != "active" or identity.get("MainPID") in (None, "0"):
        raise RuntimeError("the selected connector service is not running")
    return identity


def fresh_echo(endpoint, serial, label, timeout):
    nonce = uuid.uuid4().hex
    payload = f"recovery-probe:{label}:{serial}:{nonce}".encode()
    request = b"\x01" + len(payload).to_bytes(2, "big") + payload
    expected = b"\x81" + request[1:]
    row = {"serial": serial, "label": label, "nonce": nonce,
           "sent": time.time(), "request_sha256": hashlib.sha256(request).hexdigest()}
    connection = http.client.HTTPConnection(endpoint.hostname, endpoint.port, timeout=timeout)
    try:
        connection.request("POST", f"/v1/devices/{serial}/commands", request,
                           {"Content-Type": "application/octet-stream"})
        response = connection.getresponse()
        actual = response.read()
        row.update(http_status=response.status, response_bytes=len(actual),
                   response_sha256=hashlib.sha256(actual).hexdigest(),
                   byte_exact=actual == expected,
                   passed=response.status == 200 and actual == expected)
    except Exception as error:
        row.update(passed=False, error=repr(error))
    finally:
        connection.close()
    row["received"] = time.time()
    row["elapsed_seconds"] = row["received"] - row["sent"]
    return row


def failure_kind(directory, error):
    if error.get("status") != 200:
        # Admission, network and device errors still need kernel/log correlation
        # before attributing a failure to the physical I2C bus.
        return "http_or_transport_error"
    actual = directory / "actual.bin"
    reply = actual.read_bytes() if actual.exists() else b""
    if len(reply) == 4 and reply[:3] == b"\x7f\x00\x01":
        return "hsm_error_reply"
    return "response_mismatch"


def run(args):
    endpoint = urlsplit(args.url)
    directory = Path(args.output)
    directory.mkdir(parents=True, exist_ok=False)
    result = {"started": time.time(), "configuration": vars(args).copy(),
              "connector_before": service_identity(args.systemd_service),
              "fresh_commands": [], "intervention": "none"}
    save_json(directory / "initial.json", result)
    spec = importlib.util.spec_from_file_location(
        "i2c_connector_stress", Path(__file__).with_name("i2c-connector-stress.py"))
    stress = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(stress)
    traffic_args = types.SimpleNamespace(
        url=args.url, serials=args.serials, output=str(directory / "traffic"),
        count=args.count, seed=args.seed, max_payload=args.max_payload,
        timeout=args.timeout, scope_host=None)
    result["traffic_exit_code"] = stress.run(traffic_args)
    traffic = json.loads((directory / "traffic" / "result.json").read_text())
    result["traffic"] = traffic
    error = traffic["first_error"]
    if error is None:
        result.update(status="no_failure_observed", connector_after=service_identity(args.systemd_service))
        save_json(directory / "result.json", result)
        return 2
    result["failure_kind"] = failure_kind(directory / "traffic", error)
    order = [error["serial"]] + [serial for serial in args.serials if serial != error["serial"]]
    available = {}

    def probe(serial, label):
        row = fresh_echo(endpoint, serial, label, args.timeout)
        row["seconds_after_original_error"] = row["sent"] - error["received"]
        result["fresh_commands"].append(row)
        available[serial] = row["passed"]
        save_json(directory / "progress.json", result)
        print("FRESH " + json.dumps(row), flush=True)

    for serial in order:
        probe(serial, "immediate")
    result["immediate_success"] = dict(available)
    for index, delay in enumerate(args.retry_delays):
        pending = [serial for serial in order if not available[serial]]
        if not pending:
            break
        time.sleep(delay)
        for serial in pending:
            # A distinct nonce means a new command, never a replay.
            probe(serial, f"new-command-{index + 1}")
    if all(available.values()):
        for index in range(args.followups):
            for serial in order:
                probe(serial, f"followup-{index + 1}")
            if not all(available.values()):
                break
    result["connector_after"] = service_identity(args.systemd_service)
    before, after = result["connector_before"], result["connector_after"]
    result["connector_identity_unchanged"] = (
        None if before is None else all(before.get(key) == after.get(key) for key in
            ["MainPID", "InvocationID", "NRestarts", "ExecMainStartTimestampMonotonic"]))
    result["available_after_probe"] = available
    result["finished"] = time.time()
    passed = all(available.values()) and result["connector_identity_unchanged"] is not False
    result["status"] = "fresh_commands_passed" if passed else "recovery_failed"
    result["limits"] = (
        "Fresh Echo success does not prove an explicit recovery ioctl occurred. "
        "Correlate target counters and kernel logs. Authenticated sessions, PQC "
        "and every possible stuck-bus state remain outside this probe.")
    save_json(directory / "result.json", result)
    return 0 if passed else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:12345")
    parser.add_argument("--serials", nargs="+", required=True)
    parser.add_argument("--output", required=True, help="new evidence directory")
    parser.add_argument("--count", type=int, default=1000, help="upper bound per target; stop on first failure")
    parser.add_argument("--seed", type=int, default=91)
    parser.add_argument("--max-payload", type=int, default=8000)
    parser.add_argument("--timeout", type=float, default=75, help="HTTP timeout; allow for the connector's I2C deadline")
    parser.add_argument("--retry-delays", nargs="*", type=float, default=[1, 5], help="delays before distinct fresh commands")
    parser.add_argument("--followups", type=int, default=2)
    parser.add_argument("--systemd-service", help="optional read-only PID/invocation verification on the controller")
    args = parser.parse_args()
    endpoint = urlsplit(args.url)
    if (endpoint.scheme != "http" or not endpoint.hostname or endpoint.path not in ("", "/")
            or endpoint.query or endpoint.fragment or endpoint.username or endpoint.password):
        parser.error("URL must be a plain HTTP connector origin without credentials or a path")
    if (args.count < 1 or not math.isfinite(args.timeout) or args.timeout <= 0 or not 0 <= args.max_payload <= 8000
            or args.followups < 0 or any(not 0 <= delay <= 300 for delay in args.retry_delays)):
        parser.error("invalid count, timeout, payload, followups or delay")
    if len(set(args.serials)) != len(args.serials) or any(
            not serial.isascii() or not serial.isdecimal() for serial in args.serials):
        parser.error("serials must be unique decimal identifiers")
    raise SystemExit(run(args))


if __name__ == "__main__":
    main()
