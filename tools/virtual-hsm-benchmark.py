#!/usr/bin/env python3
"""Compare native virtual-HSM operations using disposable in-memory devices.

Builds locked firmware-full release dependencies, then separate timing and Rust
heap-profiling executables. No connectors, persistent stores, or hardware are used.
"""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import statistics
import subprocess
import sys

WEIERSTRASS = ['P-224', 'P-256', 'P-384', 'P-521', 'secp256k1',
               'Brainpool-P256', 'Brainpool-P384', 'Brainpool-P512']
SIGNING = ['RSA-2048', 'RSA-3072', 'RSA-4096', *WEIERSTRASS, 'Ed25519', 'Ed448',
           'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87']
AGREEMENT = [*WEIERSTRASS, 'X25519', 'X448']
KEMS = ['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024', 'ML-KEM-768+P-256',
        'ML-KEM-768+X25519', 'ML-KEM-1024+P-384']
ALGORITHMS = list(dict.fromkeys([*SIGNING, *AGREEMENT, *KEMS]))


def capture(command, **kwargs):
    return subprocess.check_output(command, text=True, **kwargs).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--algorithms', nargs='+', choices=ALGORITHMS, default=ALGORITHMS)
    parser.add_argument('--runs', type=int, default=3)
    parser.add_argument('--samples', type=int, default=200)
    parser.add_argument('--keygen-samples', type=int, default=3)
    parser.add_argument('--memory-samples', type=int, default=3)
    args = parser.parse_args()
    if min(args.runs, args.samples, args.keygen_samples, args.memory_samples) < 1:
        parser.error('all sample counts must be positive')
    if sys.platform not in ('linux', 'darwin'):
        parser.error('Linux or macOS is required for process memory measurement')
    root = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    build = ['cargo', 'build', '--locked', '--release', '-p', 'pkcs11rs-connector',
             '--bin', 'pkcs11rs-connector', '--features', 'firmware-full', '--message-format=json']
    print('Building locked firmware-full release dependencies', flush=True)
    artifacts = [json.loads(line) for line in capture(build, cwd=root).splitlines()]
    def library(name):
        return next(Path(filename) for item in artifacts
                    if item.get('reason') == 'compiler-artifact' and item['target']['name'] == name
                    for filename in item['filenames'] if filename.endswith('.rlib'))
    core, software = library('virtual_yubihsm_core'), library('software_key_core')
    binaries = {}
    for mode in ('timing', 'memory'):
        executable = output / f'benchmark-{mode}'
        command = ['rustc', '--edition=2024', '-O', '-Dwarnings',
                   str(root / 'tools/virtual-hsm-benchmark.rs'),
                   '--extern', f'virtual_yubihsm_core={core}',
                   '--extern', f'software_key_core={software}',
                   '-L', f'dependency={core.parent}', '-o', str(executable)]
        if mode == 'memory':
            command += ['--cfg', 'track_heap']
        subprocess.run(command, cwd=root, check=True)
        binaries[mode] = executable
    def git(repo, *args):
        return capture(['git', *args], cwd=repo)
    metadata = {
        'platform': platform.platform(), 'architecture': platform.machine(),
        'rustc': capture(['rustc', '--version']),
        'commits': {name: git(repo, 'rev-parse', 'HEAD') for name, repo in
                    [('pkcs11rs', root), ('virtual-yubihsm', root.parent / 'virtual-yubihsm'),
                     ('software-key-core', root.parent / 'software-key-core')]},
        'source_status': git(root, 'status', '--porcelain'),
        'benchmark_source_sha256': {name: hashlib.sha256((root / 'tools' / name).read_bytes()).hexdigest()
                                    for name in ('virtual-hsm-benchmark.py', 'virtual-hsm-benchmark.rs')},
        'cargo_lock_sha256': hashlib.sha256((root / 'Cargo.lock').read_bytes()).hexdigest(),
        'build': build, 'runs': args.runs,
        'scope': 'Device.execute_inner with factory authorization; fresh disposable in-memory device per algorithm/operation/process',
        'excluded': 'HTTP, USB, secure-channel encryption, login, persistence, PKCS #11 metadata and host public-key verification timings',
        'timing': 'uninstrumented release executable; native command dispatch, authorization, crypto and response allocation included; request construction and output disposal excluded; 10 warmups except keygen/keypair; keygen returns native ID only, keypair also retrieves the new public key',
        'signing': 'RSA PKCS1v1.5 and ECDSA sign prepared digests; EdDSA and pure hedged ML-DSA sign messages; message/digest length 32 except P224=28, P384/Brainpool384=48, P521/Brainpool512=64',
        'memory': 'separate executable using System allocator with atomic accounting of requested Rust allocation sizes; maximum extra live Rust heap above each operation baseline; excludes stack, allocator overhead and allocations made outside Rust',
        'retained_key_memory': 'Rust live-heap delta across first key generation; includes device bookkeeping and any lazily initialized caches, not a serialized key size',
        'process_memory': 'fresh-process peak RSS from /usr/bin/time; includes device initialization, preflight, warmups, runtime, heap, stack, and code pages; not an isolated per-operation stack measurement',
        'public_bytes': 'native GetPublicKey response excluding its algorithm byte; RSA exponent is implicit and EC points omit the SEC1 prefix; not DER/SPKI size',
        'storage': 'native object-reported key length and ceil(length/126) pages; one object record per native key; separate from RAM',
        'comparison': 'different security levels are shown explicitly; ECDH derive is one side of raw key agreement, not equivalent protocol work to KEM encapsulation/decapsulation',
    }
    if sys.platform == 'darwin':
        metadata['cpu'] = capture(['sysctl', '-n', 'machdep.cpu.brand_string'])
    else:
        metadata['cpu'] = json.loads(capture(['lscpu', '--json']))
    (output / 'metadata.json').write_text(json.dumps(metadata, indent=2) + '\n')
    # Discard all inherited provider settings and authentication material.
    env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin')}
    def measure(mode, algorithm, operation, samples):
        command = [str(binaries[mode]), algorithm, operation, str(samples)]
        if mode == 'memory':
            command = ['/usr/bin/time', '-l' if sys.platform == 'darwin' else '-v', *command]
        completed = subprocess.run(command, env=env, text=True, capture_output=True)
        if completed.returncode:
            raise RuntimeError(f'{algorithm} {operation} ({mode}) failed:\n{completed.stderr}')
        row = json.loads(completed.stdout)
        if mode == 'memory':
            pattern = (r'(\d+)\s+maximum resident set size' if sys.platform == 'darwin'
                       else r'Maximum resident set size \(kbytes\):\s*(\d+)')
            match = re.search(pattern, completed.stderr)
            if not match:
                raise RuntimeError('process memory measurement missing')
            row['process_peak_rss_bytes'] = int(match[1]) * (1 if sys.platform == 'darwin' else 1024)
        return row
    rows = []
    raw = []
    for algorithm in args.algorithms:
        operations = ['keygen', 'keypair']
        if algorithm in SIGNING:
            operations.append('sign')
        if algorithm in AGREEMENT:
            operations.append('derive')
        if algorithm in KEMS:
            operations += ['encapsulate', 'decapsulate']
        for operation in operations:
            print(f'{algorithm}: {operation}', flush=True)
            samples = args.keygen_samples if operation in ('keygen', 'keypair') else args.samples
            timings = [measure('timing', algorithm, operation, samples) for _ in range(args.runs)]
            memory = measure('memory', algorithm, operation, args.memory_samples)
            raw.append({'algorithm': algorithm, 'operation': operation, 'timing_runs': timings, 'memory_run': memory})
            rows.append({'algorithm': algorithm, 'operation': operation,
                         'median_us': statistics.median(x['median_us'] for x in timings),
                         'run_medians_us': [x['median_us'] for x in timings],
                         'timing_samples': samples * args.runs,
                         **{key: memory[key] for key in ('peak_extra_rust_heap_bytes',
                             'retained_key_rust_heap_bytes', 'process_peak_rss_bytes',
                             'native_key_bytes', 'native_key_pages', 'public_bytes', 'response_bytes')}})
            (output / 'raw.json').write_text(json.dumps(raw, indent=2) + '\n')
            (output / 'summary.json').write_text(json.dumps(rows, indent=2) + '\n')
    with (output / 'summary.csv').open('w') as f:
        writer = csv.DictWriter(f, fieldnames=[key for key in rows[0] if key != 'run_medians_us'])
        writer.writeheader()
        writer.writerows({k: v for k, v in row.items() if k != 'run_medians_us'} for row in rows)
    print(f'Results: {output / "summary.csv"}', flush=True)


if __name__ == '__main__':
    main()
