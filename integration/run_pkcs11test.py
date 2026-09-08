#!/usr/bin/env python3
"""Run the upstream pkcs11test suite on a disposable production software token."""

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

from run_clients import ClientTests, ROOT


def parse_test_names(output: str) -> list[str]:
    names = []
    suite = None
    for line in output.splitlines():
        text = line.split("#", 1)[0].strip()
        if not line.startswith(" ") and text.endswith("."):
            suite = text
        elif suite and line.startswith("  ") and re.fullmatch(r"[\w/]+", text):
            names.append(suite + text)
    return names


def write_report(path: Path, report: dict) -> None:
    counts = {}
    for case in report["cases"]:
        counts[case["status"]] = counts.get(case["status"], 0) + 1
    report["counts"] = counts
    report["complete"] = len(report["cases"]) == report["selected_count"]
    report["successful"] = report["complete"] and all(
        case["status"] in ("passed", "unsupported_or_skipped") for case in report["cases"])
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(report, indent=2) + "\n")
    temporary.replace(path)


def parse_case(name: str, xml_text: str | None, execution: dict) -> dict:
    case = {"name": name, "failures": [], "internal_skips": {}}
    if xml_text is None:
        case["status"] = ("timeout" if "timeout" in execution else
                          "crashed" if execution.get("returncode", 0) < 0 else "harness_error")
        case["failures"].append("No completed Google Test XML report was produced")
        return case
    root = ET.fromstring(xml_text)
    completed = [item for item in root.iter("testcase") if item.get("status") == "run"]
    if len(completed) != 1 or f"{completed[0].get('classname')}.{completed[0].get('name')}" != name:
        raise ValueError("Expected exactly the selected test in XML")
    case["failures"] = [item.text or item.get("message", "") for item in completed[0].findall("failure")]
    case["status"] = "failed" if case["failures"] else "passed"
    # This older suite reports TEST_SKIPPED on stderr rather than in its XML.
    reason = None
    for line in execution.get("output", "").splitlines():
        if line.startswith("Following tests were skipped because: "):
            reason = line.partition(": ")[2]
        elif reason and re.fullmatch(r"  \S+", line):
            case["internal_skips"].setdefault(reason, []).append(line.strip())
        else:
            reason = None
    if case["status"] == "passed":
        if execution.get("returncode") != 0 or "timeout" in execution:
            case["status"] = "harness_error"
            case["failures"].append("Process did not exit successfully despite passing XML")
        elif any(name in names for names in case["internal_skips"].values()):
            case["status"] = "unsupported_or_skipped"
    return case


def run_one(options, module: Path, filter_name: str) -> dict:
    fixture = ClientTests()
    started = time.monotonic()
    case = {"name": filter_name, "status": "harness_error", "failures": []}
    try:
        fixture.setUp()
        xml_path = fixture.directory / "results.xml"
        args = [options.pkcs11test, "-m", module.name, "-l", module.parent,
                "-u", fixture.env["CLIENT_USER_PIN"], "-o", fixture.env["CLIENT_SO_PIN"],
                "-I", "--gtest_also_run_disabled_tests", f"--gtest_filter={filter_name}",
                f"--gtest_output=xml:{xml_path}"]
        try:
            fixture.run_command(args)
        except AssertionError:
            pass  # Recorded command output and exit status classify this failure.
        case = parse_case(filter_name,
                          fixture.redact(xml_path.read_text()) if xml_path.exists() else None,
                          fixture.commands[-1])
    except Exception as error:
        # Setup and malformed output must not discard the other cases' results.
        message = (fixture.redact(str(error)) if hasattr(fixture, "directory")
                   else type(error).__name__)
        case = {"name": filter_name, "status": "harness_error",
                "failures": [f"Fixture or report error: {message}"]}
    finally:
        if not fixture.doCleanups():
            case["status"] = "harness_error"
            case["failures"].append("Fixture cleanup failed")
        case["commands"] = getattr(fixture, "commands", [])
        case["seconds"] = round(time.monotonic() - started, 3)
    return case


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pkcs11test", default="pkcs11test")
    parser.add_argument("--pkcs11-tool", default="pkcs11-tool")
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--filter", default="*", help="Google Test filter; default includes every test")
    parser.add_argument("--timeout", type=float, default=60, help="Per-command timeout in seconds")
    parser.add_argument("--results", type=Path, default=ROOT / "target/pkcs11test-results.json")
    parser.add_argument("--jobs", type=int, default=4, help="Independent software fixtures, 1..16")
    options = parser.parse_args()
    for name in ("pkcs11test", "pkcs11_tool", "openssl"):
        executable = shutil.which(getattr(options, name))
        if not executable:
            parser.error(f"Missing executable: {getattr(options, name)}")
        setattr(options, name, str(Path(executable).resolve()))
    if not 0 < options.timeout < float("inf") or not 1 <= options.jobs <= 16:
        parser.error("Use a finite positive timeout and 1..16 workers")

    # No arbitrary module or hardware endpoint option: -I is destructive.
    # Build the production software backend with hardware support excluded.
    target = ROOT / "target/client-tests"
    subprocess.run(["cargo", "build", "--locked", "-p", "pkcs11rs", "--no-default-features",
                    "--target-dir", str(target)], cwd=ROOT, check=True)
    filename = {"Darwin": "libpkcs11rs.dylib", "Windows": "pkcs11rs.dll"}.get(
        platform.system(), "libpkcs11rs.so")
    module = target / "debug" / filename
    ClientTests.options = argparse.Namespace(
        module=module, provider=None, pkcs11_tool=options.pkcs11_tool,
        openssl=options.openssl, hardware_token=None, discovery_pin_env=None,
        hardware_login_pin_env=None, timeout=options.timeout,
    )
    fixture = ClientTests()
    try:
        fixture.setUp()
        output = fixture.run_command([options.pkcs11test, "-m", module.name, "-l", module.parent,
            "-u", fixture.env["CLIENT_USER_PIN"], "-o", fixture.env["CLIENT_SO_PIN"], "-I",
            "--gtest_also_run_disabled_tests", f"--gtest_filter={options.filter}", "--gtest_list_tests"])
        names = parse_test_names(output)
    finally:
        fixture.doCleanups()
    if not names or len(names) != len(set(names)):
        parser.error("Expected a nonempty, unique test inventory")
    report = {
        "schema": "pkcs11rs.upstream-pkcs11test.v1", "filter": options.filter,
        "module": str(module), "module_sha256": hashlib.sha256(module.read_bytes()).hexdigest(),
        "pkcs11test": options.pkcs11test,
        "pkcs11test_sha256": hashlib.sha256(Path(options.pkcs11test).read_bytes()).hexdigest(),
        "token_initialization_enabled": True, "so_tests_enabled": True,
        "upstream_disabled_tests_enabled": True, "hardware_enabled": False,
        "fixture_isolation": "fresh token and process per test",
        "selected_count": len(names), "cases": [],
    }
    started = time.monotonic()
    write_report(options.results, report)
    print(f"Running {len(names)} upstream cases, with no inherited exclusion list", flush=True)
    with ThreadPoolExecutor(max_workers=options.jobs) as executor:
        futures = [executor.submit(run_one, options, module, name) for name in names]
        for future in as_completed(futures):
            report["cases"].append(future.result())
            report["seconds"] = round(time.monotonic() - started, 3)
            write_report(options.results, report)
            if len(report["cases"]) % 25 == 0:
                print(f"Completed {len(report['cases'])}/{len(names)}: {report['counts']}", flush=True)
    report["cases"].sort(key=lambda case: names.index(case["name"]))
    write_report(options.results, report)
    print(f"Upstream pkcs11test: {report['counts']}; successful={report['successful']}")
    print(f"Results: {options.results}")
    return 0 if report["successful"] else 1


if __name__ == "__main__":
    sys.exit(main())
