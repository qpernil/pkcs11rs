#!/usr/bin/env python3
"""Measure opaque-object allocation through an explicitly selected connector.

Requires the official Python yubihsm SDK and requests. Creates one temporary
object at a time; cleanup checks its unique label against the initial inventory.
Never fills, resets, or modifies existing objects. Password is read from stdin.
"""
import argparse
import getpass
import importlib.util
import json
from pathlib import Path
import struct
import sys
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    transport = parser.add_mutually_exclusive_group(required=True)
    transport.add_argument("--url")
    transport.add_argument("--usb", action="store_true")
    parser.add_argument("--serial", action="append", required=True)
    parser.add_argument("--authkey", type=lambda s: int(s, 0), default=1)
    parser.add_argument("--sizes", default="1,125,126,127,166,206,251,252,253")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    sizes = [int(value) for value in args.sizes.split(",")]
    if not sizes or any(not 1 <= size <= 4096 for size in sizes):
        parser.error("sizes must be between 1 and 4096 bytes")

    from yubihsm import YubiHsm
    from yubihsm.defs import ALGORITHM, CAPABILITY, COMMAND, OBJECT
    from yubihsm.objects import AuthenticationKey, Opaque

    path = Path(__file__).with_name("connector-slow-operations.py")
    spec = importlib.util.spec_from_file_location("connector_probe", path)
    helpers = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helpers)
    password = getpass.getpass("Authentication password: ") if sys.stdin.isatty() else sys.stdin.readline().rstrip("\r\n")
    results = []

    def storage(session):
        return dict(zip(
            ("total_records", "free_records", "total_pages", "free_pages", "page_size"),
            struct.unpack("!5H", session.send_secure_cmd(COMMAND.GET_STORAGE_INFO, b"")),
        ))

    for serial in args.serial:
        if args.usb:
            from yubihsm.backends.usb import UsbBackend
            backend = UsbBackend(serial=int(serial), timeout=20)
        else:
            backend = helpers.Backend(args.url, serial, 20)
        hsm = YubiHsm(backend)
        session = None
        try:
            device_info = hsm.get_device_info()
            if device_info.serial != int(serial):
                raise RuntimeError("target identity mismatch")
            session = hsm.create_session_derived(args.authkey, password)
            auth = AuthenticationKey(session, args.authkey).get_info()
            required = CAPABILITY.PUT_OPAQUE | CAPABILITY.GET_OPAQUE | CAPABILITY.DELETE_OPAQUE
            if (auth.capabilities & required != required or not auth.domains & 1
                    or not auth.delegated_capabilities & CAPABILITY.GET_OPAQUE):
                raise RuntimeError("credential lacks probe creation, inspection or cleanup rights")
            baseline = helpers.snapshot(session)
            before = storage(session)
            result = {"serial": serial, "firmware": device_info.version,
                      "baseline": before, "samples": []}
            results.append(result)
            for size in sizes:
                if before["free_records"] < 1 or before["free_pages"] * before["page_size"] < size + 1024:
                    raise RuntimeError("insufficient spare capacity for a small probe")
                label = "cap-" + uuid.uuid4().hex
                try:
                    obj = Opaque.put(session, 0, label, 1, CAPABILITY.GET_OPAQUE,
                                     ALGORITHM.OPAQUE_DATA, bytes([0xa5]) * size)
                    after = storage(session)
                    if before["free_records"] - after["free_records"] != 1:
                        raise RuntimeError("unexpected concurrent object-count change")
                    sample = {"payload_bytes": size, "reported_length": obj.get_info().size,
                              "pages": before["free_pages"] - after["free_pages"]}
                    result["samples"].append(sample)
                    print(json.dumps({"serial": serial, **sample}), flush=True)
                finally:
                    helpers.cleanup_owned(session, baseline, label, OBJECT.OPAQUE)
                    if storage(session) != before:
                        raise RuntimeError("storage did not return to baseline")
                    args.output.write_text(json.dumps(results, indent=2) + "\n")
            result["inventory_and_storage_restored"] = True
            args.output.write_text(json.dumps(results, indent=2) + "\n")
        finally:
            if session is not None:
                session.close()
            hsm.close()


if __name__ == "__main__":
    main()
