#!/usr/bin/env python3
"""Measure the shared ML-DSA/ML-KEM core and an ephemeral PKCS #11 software slot.

Builds the locked release dependencies with native hardware disabled. Runs in a
clean environment with no token store, remote connector, or hardware discovery.
Each run measures 2,000 calls after 100 warmup calls for each operation.
"""

import argparse
import csv
import io
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import tomllib


def capture(command, **kwargs):
    return subprocess.check_output(command, text=True, **kwargs).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new result directory")
    parser.add_argument("--runs", type=int, default=2)
    parser.add_argument("--offline", action="store_true", help="use cached Cargo dependencies")
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs must be positive")
    if sys.platform not in ("darwin", "linux"):
        parser.error("the benchmark supports macOS and Linux")
    root = Path(__file__).resolve().parent.parent
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    build = ["cargo", "build", "--release", "--locked", "--no-default-features", "-p", "pkcs11rs"]
    if args.offline:
        build.append("--offline")
    print("Building locked release dependencies", file=sys.stderr, flush=True)
    built = capture(build + ["--message-format=json"], cwd=root)
    artifacts = [json.loads(line) for line in built.splitlines()]
    core = next(
        Path(filename)
        for item in artifacts
        if item.get("reason") == "compiler-artifact" and item["target"]["name"] == "software_key_core"
        for filename in item["filenames"]
        if filename.endswith(".rlib")
    )
    suffix = ".dylib" if sys.platform == "darwin" else ".so"
    library = next(
        Path(filename)
        for item in artifacts
        if item.get("reason") == "compiler-artifact" and item["target"]["name"] == "pkcs11rs"
        for filename in item["filenames"]
        if filename.endswith(suffix)
    )
    executable = output / "pqc-benchmark"
    compile_command = [
        "rustc", "--edition=2024", "-O", str(root / "tools/pqc-benchmark.rs"),
        "--extern", f"software_key_core={core}",
        "-L", f"dependency={core.parent}", "-L", f"native={library.parent}",
        "-l", "dylib=pkcs11rs", "-C", f"link-arg=-Wl,-rpath,{library.parent}",
        "-o", str(executable),
    ]
    subprocess.run(compile_command, cwd=root, check=True)
    lock = tomllib.loads((root / "Cargo.lock").read_text())
    dependencies = [item for item in lock["package"] if item["name"] in ("ml-dsa", "ml-kem")]
    metadata = {
        "architecture": platform.machine(),
        "platform": platform.platform(),
        "rustc": capture(["rustc", "--version"]),
        "pkcs11rs_commit": capture(["git", "rev-parse", "HEAD"], cwd=root),
        "software_key_core_commit": capture(["git", "rev-parse", "HEAD"], cwd=root.parent / "software-key-core"),
        "dependencies": dependencies,
        "build_command": build,
        "compile_command": compile_command,
        "runs": args.runs,
        "samples_per_operation_per_run": 2000,
        "warmups_per_operation_per_run": 100,
        "message_bytes": 32,
        "signing": "hedge-preferred, operating-system randomness",
        "provider": "ephemeral authenticated software slot; in-memory session keys",
        "measurement": "single thread; per-call Instant timings; output/key cleanup outside timer; PKCS11 signing and verification include Init; signing and encapsulation include output length query; KEM includes shared-secret object publication",
        "excluded": "login, persistent storage, network, USB, and hardware operations",
    }
    if sys.platform == "linux":
        metadata["cpu"] = json.loads(capture(["lscpu", "--json"]))
    else:
        try:
            metadata["cpu"] = capture(["sysctl", "-n", "machdep.cpu.brand_string"], stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            metadata["cpu"] = platform.processor() or platform.machine()
    (output / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    # Do not inherit credentials, token stores, connector URLs or provider settings.
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PKCS11RS_HARDWARE_DISCOVERY": "0",
        "PKCS11RS_SOFTWARE_SLOTS": "pqc-benchmark",
    }
    runs = []
    for number in range(1, args.runs + 1):
        print(f"Benchmark run {number}/{args.runs}", file=sys.stderr, flush=True)
        result = capture([str(executable)], cwd=root, env=environment)
        (output / f"results-{number}.csv").write_text(result + "\n")
        rows = list(csv.DictReader(io.StringIO(result)))
        if len(rows) != 36:
            raise RuntimeError("incomplete benchmark output")
        runs.append(rows)
    summary = []
    for group in zip(*runs):
        key = tuple(group[0][field] for field in ("layer", "algorithm", "operation"))
        if any(tuple(row[field] for field in ("layer", "algorithm", "operation")) != key for row in group):
            raise RuntimeError("benchmark runs disagree on operation order")
        means = [float(row["mean_us"]) for row in group]
        mean = statistics.mean(means)
        summary.append({
            "layer": key[0], "algorithm": key[1], "operation": key[2],
            "samples_total": sum(int(row["samples"]) for row in group),
            "mean_us": round(mean, 3), "ops_per_second": round(1e6 / mean),
            "run_means_us": means,
            "run_medians_us": [float(row["median_us"]) for row in group],
            "run_p95_us": [float(row["p95_us"]) for row in group],
        })
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
