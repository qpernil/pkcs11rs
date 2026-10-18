#!/usr/bin/env python3
"""Opt-in RSA before/after timings on explicitly selected virtual HSMs.

Uses published Wycheproof private test keys, never existing device keys. Every
operation creates one labelled temporary object, deletes only that object, and
checks that the original inventory is preserved. No reset or retry of mutations.
"""
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import statistics
import time
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', required=True)
    parser.add_argument('--target', action='append', required=True, metavar='ALIAS=SERIAL')
    parser.add_argument('--phase', choices=['before', 'after'], required=True)
    parser.add_argument('--authkey', type=lambda value: int(value, 16), default=0x1007)
    parser.add_argument('--qualification-login', action='store_true')
    parser.add_argument('--allow-key-operations', action='store_true')
    parser.add_argument('--samples', type=int, default=3)
    parser.add_argument('--bits', type=int, nargs='+', default=[2048, 3072, 4096])
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.samples < 1 or any(bits not in (2048, 3072, 4096) for bits in args.bits):
        parser.error('positive sample count and SDK-supported sizes 2048/3072/4096 are required')
    if args.output.exists():
        parser.error('choose a new output file')
    pairs = [value.split('=', 1) for value in args.target]
    if any(len(pair) != 2 or not pair[0] or not pair[1].isdigit() for pair in pairs):
        parser.error('targets must be ALIAS=SERIAL')
    targets = dict(pairs)
    if len(targets) != len(pairs) or len(set(targets.values())) != len(targets):
        parser.error('target aliases and serials must be unique')
    spec = importlib.util.spec_from_file_location('qualification', Path(__file__).with_name('connector-slow-operations.py'))
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    import getpass
    import requests
    from cryptography.hazmat.primitives import serialization
    from yubihsm import YubiHsm
    from yubihsm.defs import ALGORITHM, CAPABILITY, OBJECT
    from yubihsm.objects import AsymmetricKey, AuthenticationKey, PublicWrapKey
    vectors = Path(__file__).resolve().parents[2] / 'software-key-core/tests/vectors/wycheproof'
    keys = {}
    for bits in args.bits:
        data = json.loads(gzip.decompress((vectors / f'rsa_oaep_{bits}_sha256_mgf1sha256_test.json.gz').read_bytes()))
        encoded = bytes.fromhex(data['testGroups'][0]['privateKeyPkcs8'])
        keys[bits] = serialization.load_der_private_key(encoded, None)
    available = requests.get(args.url.rstrip('/') + '/v1/devices', timeout=10)
    available.raise_for_status()
    devices = {str(device['serial']): device for device in available.json()['devices']}
    for serial in targets.values():
        if serial not in devices or devices[serial]['status'] != 'claimed':
            raise RuntimeError('an explicitly selected device is unavailable')
    report = {'phase': args.phase, 'results': [], 'inventories_restored': {},
              'test_key_moduli_sha256': {str(bits): hashlib.sha256(
                  key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
              ).hexdigest() for bits, key in keys.items()}}
    baseline = {}
    hsms = {}

    def login(hsm, alias):
        password = 'password' if args.qualification_login else getpass.getpass(f'{alias} password: ')
        try:
            return hsm.create_session_derived(args.authkey, password)
        finally:
            del password

    def save():
        args.output.write_text(json.dumps(report, indent=2) + '\n')

    try:
        for alias, serial in targets.items():
            hsm = YubiHsm(helper.Backend(args.url, serial, 1200))
            hsms[alias] = hsm
            if str(hsm.get_device_info().serial) != serial:
                raise RuntimeError('device identity mismatch')
            session = login(hsm, alias)
            try:
                info = AuthenticationKey(session, args.authkey).get_info()
                required = (CAPABILITY.GENERATE_ASYMMETRIC_KEY | CAPABILITY.PUT_ASYMMETRIC |
                            CAPABILITY.DELETE_ASYMMETRIC_KEY | CAPABILITY.PUBLIC_WRAP_KEY_WRITE |
                            CAPABILITY.PUBLIC_WRAP_KEY_DELETE)
                if (info.capabilities & required != required or not info.domains & 1 or
                        info.delegated_capabilities & (CAPABILITY.SIGN_PKCS | CAPABILITY.EXPORT_WRAPPED)
                        != (CAPABILITY.SIGN_PKCS | CAPABILITY.EXPORT_WRAPPED)):
                    raise RuntimeError('credential lacks benchmark permissions')
                baseline[alias] = helper.snapshot(session)
            finally:
                session.close()
        report['status'] = 'preflight_passed'
        save()
        print('All selected devices passed identity, authorization and inventory preflight', flush=True)
        if not args.allow_key_operations:
            return
        for alias, hsm in hsms.items():
            for bits, key in keys.items():
                for operation in ['private_import', 'public_import', 'generate']:
                    for sample in range(args.samples):
                        session = login(hsm, alias)
                        label = 'p11-rsa-' + uuid.uuid4().hex[:24]
                        kind = OBJECT.PUBLIC_WRAP_KEY if operation == 'public_import' else OBJECT.ASYMMETRIC_KEY
                        try:
                            if helper.snapshot(session) != baseline[alias]:
                                raise RuntimeError('inventory changed; no operation started')
                            report['pending'] = {'target': alias, 'label': label, 'type': kind.name}
                            save()
                            print(json.dumps({'target': alias, 'bits': bits, 'operation': operation,
                                              'sample': sample + 1, 'status': 'starting'}), flush=True)
                            started = time.monotonic()
                            if operation == 'generate':
                                obj = AsymmetricKey.generate(session, 0, label, 1, CAPABILITY.SIGN_PKCS,
                                                             getattr(ALGORITHM, f'RSA_{bits}'))
                            elif operation == 'private_import':
                                obj = AsymmetricKey.put(session, 0, label, 1, CAPABILITY.SIGN_PKCS, key)
                            else:
                                obj = PublicWrapKey.put(session, 0, label, 1, CAPABILITY.EXPORT_WRAPPED,
                                                        CAPABILITY(0), key.public_key())
                            elapsed = time.monotonic() - started
                            # Validation below is outside the measured operation.
                            if obj.get_public_key().key_size != bits:
                                raise RuntimeError('unexpected resulting key size')
                        finally:
                            # Long keygen can outlive an idle-session timeout. Authenticate
                            # freshly for inspection/cleanup; never replay the creation command.
                            try:
                                session.close()
                            except Exception:
                                pass
                            cleanup = login(hsm, alias)
                            try:
                                deleted = helper.cleanup_owned(cleanup, baseline[alias], label, kind)
                            finally:
                                cleanup.close()
                        if deleted != 1:
                            raise RuntimeError('expected exactly one owned temporary object')
                        del report['pending']
                        report['inventories_restored'][alias] = True
                        row = {'target': alias, 'bits': bits, 'operation': operation, 'seconds': elapsed}
                        report['results'].append(row)
                        save()
                        print(json.dumps(row), flush=True)
        report['status'] = 'passed'
        report['summary'] = []
        for alias in targets:
            for bits in args.bits:
                for operation in ['private_import', 'public_import', 'generate']:
                    samples = [row['seconds'] for row in report['results'] if
                               (row['target'], row['bits'], row['operation']) == (alias, bits, operation)]
                    report['summary'].append({'target': alias, 'bits': bits, 'operation': operation,
                                              'median_seconds': statistics.median(samples)})
        save()
    finally:
        for hsm in hsms.values():
            hsm.close()


if __name__ == '__main__':
    main()
