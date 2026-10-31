#!/usr/bin/env python3
"""Non-mutating, byte-exact I2C YubiHSM echo stress test (Linux, stdlib only)."""
import argparse
import fcntl
import os
import random
import select
import struct
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("address", type=lambda value: int(value, 0))
    parser.add_argument("--bus", default="/dev/i2c-1")
    parser.add_argument("--ready", required=True, help="GPIOCHIP:OFFSET (active low)")
    parser.add_argument("--count", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--max-payload", type=int, default=3133)
    parser.add_argument("--payload-gap-ms", type=float, default=0)
    parser.add_argument("--abandon-every", type=int, default=0, help="leave the last payload byte unread every N exchanges")
    parser.add_argument("--supersede-every", type=int, default=0, help="replace every Nth request twice before reading a response")
    args = parser.parse_args()
    if not 0x08 <= args.address <= 0x77 or not 0 <= args.max_payload <= 3133:
        parser.error("invalid address or payload limit")
    bus = os.open(args.bus, os.O_RDWR)
    fcntl.ioctl(bus, 0x0703, args.address)
    ready = None
    if args.ready:
        chip, offset = args.ready.rsplit(":", 1)
        with open(chip, "rb", buffering=0) as gpio:
            request = bytearray(592)
            struct.pack_into("I", request, 0, int(offset))
            request[256:266] = b"i2c-stress"
            struct.pack_into("Q", request, 288, (1 << 2) | (1 << 8) | (1 << 4))
            struct.pack_into("I", request, 560, 1)
            fcntl.ioctl(gpio, 0xC250B407, request)
            ready = struct.unpack_from("i", request, 588)[0]

    def asserted():
        value = bytearray(struct.pack("QQ", 0, 1))
        fcntl.ioctl(ready, 0xC010B40E, value)
        return not (struct.unpack_from("Q", value)[0] & 1)

    def read(length):
        result = os.read(bus, length)
        if len(result) != length:
            raise RuntimeError(f"short read: {len(result)} of {length}")
        return result

    def check_deadline(deadline, stage):
        if time.monotonic() >= deadline:
            raise TimeoutError(stage)

    def write_request(request, deadline, recovery=False, token=0):
        fcntl.flock(bus, fcntl.LOCK_EX)
        fcntl.ioctl(bus, 0x0701, 0)  # Never replay a partial transfer after arbitration loss.
        while select.select([ready], [], [], 0)[0]:
            os.read(ready, 48)
        if os.write(bus, request) != len(request):
            raise RuntimeError("short request write")
        while True:
            check_deadline(deadline, "request cleanup acknowledgement")
            if not select.select([ready], [], [], max(0, deadline - time.monotonic()))[0]:
                raise TimeoutError("request cleanup acknowledgement")
            event = os.read(ready, 48)
            if len(event) != 48:
                raise RuntimeError("short GPIO event")
            if struct.unpack_from("I", event, 8)[0] == 1:
                break
        if not recovery:
            fcntl.flock(bus, fcntl.LOCK_UN)

    def recover(deadline):
        token = time.monotonic_ns() & 0xffffffff
        try:
            request = b"\x00\x00\x0dBSCRECOV\x01" + token.to_bytes(4, "big")
            write_request(request, deadline, recovery=True, token=token)
            while not asserted():
                check_deadline(deadline, "recovery response")
                time.sleep(0.0001)
            expected = b"\x80\x00\x0dBSCRECOV\x01" + token.to_bytes(4, "big")
            header = read(3)
            if header != expected[:3] or read(len(expected) - 3) != expected[3:]:
                raise RuntimeError("target frontend did not confirm explicit recovery")
        finally:
            fcntl.flock(bus, fcntl.LOCK_UN)

    recover(time.monotonic() + 5)
    needs_recovery = False
    rng = random.Random(args.seed)
    boundaries = [0, 1, 2, 12, 13, 14, 15, 16, 17, 31, 32, 255, 256, 1024, 3133]
    sizes = [n for n in boundaries if n <= args.max_payload]
    started = time.monotonic()
    total = 0
    for index in range(args.count):
        length = sizes[index] if index < len(sizes) else rng.randrange(args.max_payload + 1)
        if args.supersede_every and args.max_payload:
            length = max(1, length)
        payload = rng.randbytes(length)
        request = b"\x01" + length.to_bytes(2, "big") + payload
        deadline = time.monotonic() + 5
        try:
            if needs_recovery:
                recover(deadline)
                needs_recovery = False
            write_request(request, deadline)
            if args.supersede_every and (index + 1) % args.supersede_every == 0:
                # Let a deliberately delayed worker enter its response write.
                time.sleep(0.05)
                for _ in range(2):
                    recover(deadline)
                    payload = bytes((byte + 1) % 256 for byte in payload)
                    request = b"\x01" + length.to_bytes(2, "big") + payload
                    write_request(request, deadline)
            while not asserted():
                check_deadline(deadline, "response ready")
                time.sleep(0.0001)
            fcntl.flock(bus, fcntl.LOCK_EX)
            fcntl.ioctl(bus, 0x0701, 0)
            header = read(3)
            if header != b"\x81" + request[1:3]:
                raise RuntimeError(f"wrong header {header.hex()}, expected 81{request[1:3].hex()}")
            if length:
                time.sleep(args.payload_gap_ms / 1000)
                abandon = args.abandon_every and (index + 1) % args.abandon_every == 0
                needs_recovery = bool(abandon)
                wanted = length - 1 if abandon else length
                response = read(wanted) if wanted else b""
                if response != payload[:wanted]:
                    first = next(i for i, (a, b) in enumerate(zip(response, payload)) if a != b)
                    raise RuntimeError(f"payload mismatch at byte {first} of {length}")
            total += length
        except Exception as error:
            raise RuntimeError(f"exchange={index} payload={length} seed={args.seed}: {error}") from error
        finally:
            fcntl.flock(bus, fcntl.LOCK_UN)
        if (index + 1) % 100 == 0:
            print(f"PASS {index + 1} exchanges, {total} payload bytes", flush=True)
    print(f"PASS {args.count} exchanges in {time.monotonic() - started:.2f}s", flush=True)
    os.close(bus)
    if ready is not None:
        os.close(ready)


if __name__ == "__main__":
    main()
