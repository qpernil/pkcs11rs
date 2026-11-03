#!/usr/bin/env python3
"""Keep six public-fixture OATH credentials on an explicitly selected test key.

Uses the exported PKCS #11 ABI. Never overwrites or deletes credentials, changes
the OATH password, or accesses another application. Re-running preserves names
already present with the expected type and hash. Their secrets are not read.
"""

import argparse

from oath_smoke import Module


HASHES = [
    ("SHA1", 0x220, b"12345678901234567890"),
    ("SHA256", 0x250, b"12345678901234567890123456789012"),
    ("SHA512", 0x270, b"1234567890" * 6 + b"1234"),
]


def matching_views(module, name, key_type, hash_type):
    return [
        key for key in module.find(key_type, hash_type)
        if module.attr(key, 0x102) == name
    ]


def verify(module, samples):
    for name, totp, hash_type in samples:
        kind = 0xD0530002 if totp else 0xD0530003
        views = matching_views(module, name, kind, hash_type)
        if len(views) != 1:
            raise RuntimeError(f"Expected one extended view for {name.decode()}")
        if module.attr(views[0], 1) != b"\x01":
            raise RuntimeError("Sample is not a persistent token object")
        if not totp and hash_type == 0x220:
            if len(matching_views(module, name, 0x23, hash_type)) != 1:
                raise RuntimeError("Standard SHA1 HOTP view is missing")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module", required=True)
    parser.add_argument("--serial", required=True)
    args = parser.parse_args()
    if args.serial in {"10462967", "12345678"}:
        parser.error("Select a dedicated physical test YubiKey")

    samples = []
    module = Module(args.module, args.serial)
    try:
        module.login_empty()
        baseline = set(module.names())
        for totp in [False, True]:
            for hash_name, hash_type, secret in HASHES:
                name = f"pkcs11rs-smoke:{'TOTP' if totp else 'HOTP'}-{hash_name}".encode()
                samples.append((name, totp, hash_type))
                if name in baseline:
                    # The device cannot export the secret. Validate public
                    # identity only; an existing credential is never replaced.
                    verify(module, [(name, totp, hash_type)])
                    print(f"Preserved existing {name.decode()}")
                else:
                    module.create(name, secret, totp=totp, hash_=hash_type)
                    print(f"Created persistent {name.decode()}")
        verify(module, samples)
        if set(module.names()) != baseline | {name for name, _, _ in samples}:
            raise RuntimeError("Unexpected change to the OATH inventory")
    finally:
        module.close()

    # Verify persistence after finalization with a fresh module instance. No
    # HOTP calculations are performed, so newly created counters remain zero.
    module = Module(args.module, args.serial)
    try:
        module.login_empty()
        verify(module, samples)
        print("Verified six persistent credentials and seven PKCS #11 views after reinitialization")
    finally:
        module.close()


if __name__ == "__main__":
    main()
