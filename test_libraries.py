"""Build isolated test libraries while sharing Cargo's dependency artifacts."""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import platform
import shutil
from subprocess import run as run_cargo

ROOT = Path(__file__).resolve().parent
ENVIRONMENT = {
    "abi": "PKCS11RS_ABI_TEST_LIBRARY",
    "embedded": "PKCS11RS_EMBEDDED_VIRTUAL_YUBIKEY_TEST_LIBRARY",
}
FEATURES = {
    "abi": ["--features", "abi-tests"],
    "embedded": ["--no-default-features", "--features", "embedded-virtual-yubikey"],
    "software": ["--no-default-features"],
}


_selected_libraries: dict[str, Path] = {}


def filename() -> str:
    return {"Darwin": "libpkcs11rs.dylib", "Windows": "pkcs11rs.dll"}.get(
        platform.system(), "libpkcs11rs.so")


def configured_library(variant: str) -> Path | None:
    name = ENVIRONMENT.get(variant)
    value = os.environ.get(name) if name else None
    if value is None:
        return None
    path = Path(value).resolve(strict=True)
    if not path.is_file():
        raise ValueError(f"{name} must identify a shared library: {path}")
    return path


def build_library(variant: str) -> Path:
    # Cargo fingerprints features itself. All configurations reuse unchanged
    # dependencies, including artifacts produced by the ordinary Rust tests.
    target = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
    if not target.is_absolute():
        target = ROOT / target
    target = target.resolve()
    run_cargo([
        "cargo", "build", "--locked", "-p", "pkcs11rs",
        *FEATURES[variant], "--target-dir", str(target),
    ], cwd=ROOT, check=True)
    artifact = target / "debug" / filename()
    hasher = hashlib.sha256()
    with artifact.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(chunk)
    digest = hasher.hexdigest()
    snapshot = ROOT / "target" / "test-libraries" / variant / digest / filename()
    snapshot.parent.mkdir(parents=True, exist_ok=True)
    # A loaded Windows DLL cannot be overwritten. Content-addressed paths
    # also prevent the dynamic loader from reusing another feature variant.
    if not snapshot.exists():
        shutil.copy2(artifact, snapshot)
    return snapshot


def selected_library(variant: str) -> Path | None:
    return _selected_libraries.get(variant) or configured_library(variant)


def ensure_library(variant: str) -> Path:
    path = selected_library(variant)
    if path is None:
        path = build_library(variant)
        os.environ[ENVIRONMENT[variant]] = str(path)
    _selected_libraries[variant] = path
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--github-env", action="store_true",
                        help="Export the built library paths to subsequent Actions steps")
    args = parser.parse_args()
    paths = {ENVIRONMENT[variant]: build_library(variant) for variant in ENVIRONMENT}
    for name, path in paths.items():
        print(f"{name}={path}", flush=True)
    if args.github_env:
        with Path(os.environ["GITHUB_ENV"]).open("a", encoding="utf-8") as output:
            for name, path in paths.items():
                output.write(f"{name}={path}\n")


if __name__ == "__main__":
    main()
