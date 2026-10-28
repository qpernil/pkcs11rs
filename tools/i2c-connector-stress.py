#!/usr/bin/env python3
"""Non-mutating, byte-exact echo qualification through an existing connector.

Run on the I2C controller with a loopback connector URL to exclude SSH forwarding
from the request path. Does not discover hardware, authenticate, or mutate keys.
"""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import random
import socket
import threading
import time
from urllib.parse import urlsplit


def save_json(path, value):
    with path.open("w") as output:
        json.dump(value, output, indent=2)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())


def freeze_scope(host):
    """Force the configured acquisition, then stop; retain timing, not assumptions."""
    event = {"command_time": time.time()}
    try:
        with socket.create_connection((host, 5025), timeout=2) as scope:
            scope.sendall(b":TRIG:MODE FTRIG\n")
            time.sleep(0.15)
            scope.sendall(b":STOP\n:TRIG:STAT?\n")
            reply = bytearray()
            while not reply.endswith(b"\n"):
                chunk = scope.recv(4096)
                if not chunk:
                    raise EOFError("scope closed before status reply")
                reply.extend(chunk)
            event["status"] = reply.decode().strip()
    except Exception as error:
        event["error"] = repr(error)
    event["finished"] = time.time()
    return event


def run(args):
    endpoint = urlsplit(args.url)
    directory = Path(args.output)
    directory.mkdir(parents=True, exist_ok=False)
    save_json(directory / "run.json", {**vars(args), "started": time.time()})
    stopped = threading.Event()
    error_lock = threading.Lock()
    first_error = []
    results = []

    def worker(serial, seed):
        rng = random.Random(seed)
        boundaries = [0, 1, 2, 15, 16, 17, 31, 32, 255, 256, 1024, 3133, 4093, 4668, 8000]
        sizes = [length for length in boundaries if length <= args.max_payload]
        bulk = [length for length in [31, 255, 1024, 2441, 3133, 4093, 4668, 8000]
                if length <= args.max_payload] or sizes
        completed = total = 0
        started = time.monotonic()
        connection = http.client.HTTPConnection(endpoint.hostname, endpoint.port, timeout=args.timeout)
        with (directory / (serial + ".jsonl")).open("w", buffering=1) as log:
            for index in range(args.count):
                if stopped.is_set():
                    break
                length = sizes[index % len(sizes)] if index < 60 else rng.choice(bulk)
                payload = rng.randbytes(length)
                request = b"\x01" + length.to_bytes(2, "big") + payload
                expected = b"\x81" + request[1:]
                record = {"serial": serial, "index": index, "payload_length": length,
                          "sent": time.time(), "request_sha256": hashlib.sha256(request).hexdigest()}
                actual = None
                try:
                    connection.request("POST", f"/v1/devices/{serial}/commands", request,
                                       {"Content-Type": "application/octet-stream"})
                    response = connection.getresponse()
                    actual = response.read()
                    record.update(status=response.status, received=time.time(),
                                  response_length=len(actual),
                                  response_sha256=hashlib.sha256(actual).hexdigest())
                    if response.status != 200:
                        record["error"] = "HTTP status " + str(response.status)
                        record["error_body"] = actual.decode(errors="replace")
                    elif actual != expected:
                        record["error"] = "byte mismatch"
                        record["first_differing_offset"] = next(
                            (i for i, (a, b) in enumerate(zip(expected, actual)) if a != b),
                            min(len(expected), len(actual)))
                except Exception as error:
                    record.update(error=repr(error), received=time.time())
                log.write(json.dumps(record) + "\n")
                if "error" in record:
                    log.flush()
                    os.fsync(log.fileno())
                    with error_lock:
                        if not first_error:
                            first_error.append(record)
                            stopped.set()
                            save_json(directory / "first-error.json", record)
                            (directory / "expected.bin").write_bytes(expected)
                            if actual is not None:
                                (directory / "actual.bin").write_bytes(actual)
                            if args.scope_host:
                                save_json(directory / "scope-stop.json", freeze_scope(args.scope_host))
                    break
                completed += 1
                total += length
                if completed % 100 == 0:
                    print(f"{serial}: PASS {completed} exchanges, {total} payload bytes", flush=True)
        connection.close()
        result = {"serial": serial, "completed": completed, "payload_bytes": total,
                  "elapsed_seconds": time.monotonic() - started,
                  "status": "passed" if completed == args.count else "stopped"}
        results.append(result)
        print(json.dumps(result), flush=True)

    threads = [threading.Thread(target=worker, args=(serial, args.seed + i))
               for i, serial in enumerate(args.serials)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    passed = len(results) == len(args.serials) and all(row["status"] == "passed" for row in results)
    summary = {"passed": passed, "finished": time.time(), "results": results,
               "first_error": first_error[0] if first_error else None}
    save_json(directory / "result.json", summary)
    return 0 if passed else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:22346")
    parser.add_argument("--serials", nargs="+", required=True)
    parser.add_argument("--output", required=True, help="new evidence directory; must not exist")
    parser.add_argument("--count", type=int, default=1000, help="exchanges per serial")
    parser.add_argument("--seed", type=int, default=91)
    parser.add_argument("--max-payload", type=int, default=8000)
    parser.add_argument("--timeout", type=float, default=10)
    parser.add_argument("--scope-host", help="optional preconfigured Siglent; freeze at first error")
    args = parser.parse_args()
    endpoint = urlsplit(args.url)
    if endpoint.scheme != "http" or not endpoint.hostname or endpoint.path not in ("", "/") or endpoint.query or endpoint.fragment or endpoint.username or endpoint.password:
        parser.error("URL must be a plain HTTP connector origin without credentials or a path")
    if args.count < 1 or args.timeout <= 0 or not 0 <= args.max_payload <= 8000:
        parser.error("invalid count, timeout, or payload limit")
    if len(set(args.serials)) != len(args.serials) or any(not serial.isascii() or not serial.isdecimal() for serial in args.serials):
        parser.error("serials must be unique decimal identifiers")
    raise SystemExit(run(args))


if __name__ == "__main__":
    main()
