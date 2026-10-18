#!/usr/bin/env python3
"""Opt-in RSA-4096/import timing and overload checks through serial-addressed HTTP.

Requires the official Python yubihsm SDK and requests. This never initializes
local hardware discovery, resets devices, or modifies existing objects. Output
uses caller-provided aliases rather than device identifiers. Run --help first.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import getpass
import hashlib
import json
from pathlib import Path
import statistics
import threading
import time
import uuid


ECHO = b"\x01\x00\x05probe"
ECHO_REPLY = b"\x81\x00\x05probe"


def snapshot(session):
    import struct
    from yubihsm.defs import COMMAND
    # Preserve vendor algorithm metadata even when the SDK cannot decode its enum.
    return {(obj.object_type, obj.id): session.send_secure_cmd(
        COMMAND.GET_OBJECT_INFO, struct.pack("!HB", obj.id, obj.object_type))
        for obj in session.list_objects()}


def cleanup_owned(session, baseline, label, object_type):
    """Only delete a new object with the exact unpredictable operation label."""
    candidates = []
    for obj in session.list_objects(label=label):
        info = obj.get_info()
        if info.label != label or info.object_type != object_type:
            raise RuntimeError("cleanup refused: unexpected object identity")
        if (info.object_type, info.id) in baseline:
            raise RuntimeError("cleanup refused: object existed before the test")
        candidates.append((obj, info))
    if len(candidates) > 1:
        raise RuntimeError("cleanup refused: ambiguous operation label")
    for obj, info in candidates:
        if obj.get_info() != info:
            raise RuntimeError("cleanup refused: object changed during inspection")
        obj.delete()
    if snapshot(session) != baseline:
        raise RuntimeError("inventory differs after cleanup; no unrelated objects were deleted")
    return len(candidates)


def summary(samples):
    if not samples:
        return {"count": 0}
    values = sorted(samples)
    return {"count": len(values), "median_ms": round(statistics.median(values) * 1000, 3),
            "p95_ms": round(values[min(len(values) - 1, int(len(values) * .95))] * 1000, 3),
            "max_ms": round(max(values) * 1000, 3)}


class Backend:
    def __init__(self, url, serial, timeout):
        import requests
        self.http = requests.Session()
        self.url = f"{url.rstrip('/')}/v1/devices/{serial}/commands"
        self.timeout = timeout

    def transceive(self, msg):
        # requests defaults to zero retries. An uncertain mutation must never be replayed.
        response = self.http.post(self.url, data=msg,
                                  headers={"Content-Type": "application/octet-stream"},
                                  timeout=(5, self.timeout))
        response.raise_for_status()
        return response.content

    def close(self):
        self.http.close()


def probe(url):
    import requests
    started = time.monotonic()
    try:
        response = requests.post(url, data=ECHO, timeout=(2, 1200))
        status = str(response.status_code)
        if response.status_code == 200 and response.content != ECHO_REPLY:
            status = "invalid_echo"
    except requests.RequestException:
        status = "transport_error"
    return status, time.monotonic() - started


class Probes:
    def __init__(self, urls):
        self.urls = urls
        self.stop = threading.Event()
        self.samples = {name: [] for name in urls}
        self.threads = [threading.Thread(target=self.run, args=(name, url))
                        for name, url in urls.items()]

    def run(self, name, url):
        while not self.stop.is_set():
            self.samples[name].append(probe(url))
            self.stop.wait(.1)

    def __enter__(self):
        for thread in self.threads:
            thread.start()
        return self

    def __exit__(self, *args):
        self.stop.set()
        for thread in self.threads:
            thread.join()

    def report(self):
        return {name: {"statuses": {status: sum(s == status for s, _ in samples)
                                   for status in sorted({s for s, _ in samples})},
                       "latency": summary([t for s, t in samples if s == "200"])}
                for name, samples in self.samples.items()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--target", action="append", required=True, metavar="ALIAS=SERIAL")
    parser.add_argument("--authkey", type=lambda text: int(text, 16), default=0x1007)
    parser.add_argument("--qualification-login", action="store_true",
                        help="use the deliberately known qualification password from README")
    parser.add_argument("--allow-key-operations", action="store_true",
                        help="create and delete only this run's temporary objects")
    parser.add_argument("--samples", type=int, default=1)
    parser.add_argument("--overload", action="store_true",
                        help="add one public-wrap import with 80 queued Echo requests per target")
    parser.add_argument("--timeout", type=int, default=1200)
    parser.add_argument("--public-key", type=Path, required=True,
                        help="reuse this public PEM; if absent, save the first generated public key")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.samples < 1 or args.timeout < 1:
        parser.error("samples and timeout must be positive")
    pairs = [target.split("=", 1) for target in args.target]
    if any(len(pair) != 2 or not pair[0] or not pair[1].isdigit() for pair in pairs):
        parser.error("targets must be ALIAS=SERIAL")
    targets = dict(pairs)
    if len(targets) != len(pairs) or len(set(targets.values())) != len(targets):
        parser.error("target aliases and serials must be unique")
    if args.output.exists():
        parser.error("output already exists; choose a fresh report path")
    from cryptography.hazmat.primitives import serialization
    from yubihsm import YubiHsm
    from yubihsm.defs import ALGORITHM, CAPABILITY, OBJECT
    from yubihsm.objects import AsymmetricKey, AuthenticationKey, PublicWrapKey
    import requests
    inventory = requests.get(args.url.rstrip('/') + "/v1/devices", timeout=5)
    inventory.raise_for_status()
    available = {d["serial"]: d for d in inventory.json()["devices"]}
    for serial in targets.values():
        if serial not in available or available[serial]["status"] != "claimed":
            raise RuntimeError("an explicitly requested target is not claimed")
    public_key = (serialization.load_pem_public_key(args.public_key.read_bytes())
                  if args.public_key.exists() else None)
    if public_key is not None and public_key.key_size != 4096:
        raise RuntimeError("the shared public key must be RSA-4096")
    sessions = {}
    report = {"results": [], "inventories_restored": {}, "qualification": "preflight"}

    def save():
        args.output.write_text(json.dumps(report, indent=2) + "\n")

    def authenticate(hsm, name):
        password = "password" if args.qualification_login else getpass.getpass(f"{name} password: ")
        try:
            return hsm.create_session_derived(args.authkey, password)
        finally:
            del password

    try:
        # Authenticate every target before any mutation; don't leave idle sessions to expire.
        for name, serial in targets.items():
            hsm = YubiHsm(Backend(args.url, serial, args.timeout))
            sessions[name] = [hsm, None, None]
            if str(hsm.get_device_info().serial) != serial:
                raise RuntimeError("target identity mismatch")
            session = authenticate(hsm, name)
            sessions[name][1] = session
            auth = AuthenticationKey(session, args.authkey).get_info()
            required = (CAPABILITY.GENERATE_ASYMMETRIC_KEY | CAPABILITY.PUBLIC_WRAP_KEY_WRITE |
                        CAPABILITY.DELETE_ASYMMETRIC_KEY | CAPABILITY.PUBLIC_WRAP_KEY_DELETE)
            delegated = CAPABILITY.SIGN_PKCS | CAPABILITY.EXPORT_WRAPPED
            if (auth.capabilities & required != required or not auth.domains & 1 or
                    auth.delegated_capabilities & delegated != delegated):
                raise RuntimeError("qualification credential lacks required permissions")
            sessions[name][2] = snapshot(session)
            session.close()
            sessions[name][1] = None
        print("All explicitly selected targets passed identity and permission preflight", flush=True)
        if not args.allow_key_operations:
            save()
            return
        report["qualification"] = "running"
        save()
        urls = {name: f"{args.url.rstrip('/')}/v1/devices/{serial}/commands"
                for name, serial in targets.items()}
        for name, (hsm, _, baseline) in sessions.items():
            session = authenticate(hsm, name)
            sessions[name][1] = session
            if snapshot(session) != baseline:
                raise RuntimeError("inventory changed after preflight; no new operation was started")
            operations = (["rsa4096_generate"] * args.samples +
                          ["rsa4096_public_wrap_import"] * args.samples +
                          (["public_wrap_import_overload"] if args.overload else []))
            for operation in operations:
                label = "p11-bench-" + uuid.uuid4().hex[:24]
                kind = OBJECT.ASYMMETRIC_KEY if operation == "rsa4096_generate" else OBJECT.PUBLIC_WRAP_KEY
                report["pending"] = {"target": name, "label": label, "type": kind.name}
                save()
                print(json.dumps({"target": name, "operation": operation, "status": "starting"}), flush=True)
                with Probes({alias: url for alias, url in urls.items() if alias != name}) as probes:
                    burst = []
                    def queued_echoes():
                        time.sleep(.25)
                        with ThreadPoolExecutor(max_workers=80) as executor:
                            burst.extend(executor.map(probe, [urls[name]] * 80))
                    worker = threading.Thread(target=queued_echoes) if operation.endswith("overload") else None
                    started = time.monotonic()
                    try:
                        if worker:
                            worker.start()
                        if operation == "rsa4096_generate":
                            obj = AsymmetricKey.generate(session, 0, label, 1, CAPABILITY.SIGN_PKCS, ALGORITHM.RSA_4096)
                        else:
                            obj = PublicWrapKey.put(session, 0, label, 1, CAPABILITY.EXPORT_WRAPPED,
                                                    CAPABILITY(0), public_key)
                        elapsed = time.monotonic() - started
                        if operation == "rsa4096_generate" and public_key is None:
                            public_key = obj.get_public_key()
                            encoded = public_key.public_bytes(serialization.Encoding.PEM,
                                                              serialization.PublicFormat.SubjectPublicKeyInfo)
                            with args.public_key.open("xb") as output:
                                output.write(encoded)
                    finally:
                        if worker:
                            worker.join()
                        cleaned = cleanup_owned(session, baseline, label, kind)
                if cleaned != 1:
                    raise RuntimeError("the operation did not produce exactly one owned temporary object")
                status, recovery_time = probe(urls[name])
                if status != "200":
                    raise RuntimeError("target Echo did not recover after the operation")
                row = {"target": name, "operation": operation, "seconds": round(elapsed, 6),
                       "other_target_probes": probes.report(), "recovery_ms": round(recovery_time * 1000, 3)}
                if worker:
                    row["burst"] = {status: summary([t for s, t in burst if s == status])
                                    for status in sorted({s for s, _ in burst})}
                del report["pending"]
                report["results"].append(row)
                report["inventories_restored"][name] = True
                save()
                print(json.dumps(row), flush=True)
            session.close()
            sessions[name][1] = None
        report["public_key_sha256"] = hashlib.sha256(args.public_key.read_bytes()).hexdigest()
        report["qualification"] = "passed"
        save()
    finally:
        for hsm, session, _ in sessions.values():
            try:
                if session:
                    session.close()
            finally:
                hsm.close()


if __name__ == "__main__":
    main()
