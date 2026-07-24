#!/usr/bin/env python3
"""Run selected OASIS PKCS #11 v3.2 mandatory profile cases."""

from __future__ import annotations

import argparse
import os
import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from conformance.test_oasis import OasisProfileTests  # noqa: E402


TEST_METHODS = {
    "BL-M-1-32": "test_BL_M_1_32",
    "EXT-M-1-32": "test_EXT_M_1_32",
    "AUTH-M-1-32": "test_AUTH_M_1_32",
    "CERT-M-1-32": "test_CERT_M_1_32",
}


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Execute the final OASIS PKCS #11 v3.2 mandatory provider "
            "profile XML cases. Without --module, the deterministic ABI "
            "test backend is built and used."
        )
    )
    parser.add_argument(
        "--module",
        type=pathlib.Path,
        help="production PKCS #11 shared library",
    )
    parser.add_argument(
        "--slot",
        type=lambda value: int(value, 0),
        help="slot ID to qualify; required with --module",
    )
    parser.add_argument(
        "--case",
        action="append",
        choices=tuple(TEST_METHODS),
        dest="cases",
        help="case to execute; repeat as needed (default: all)",
    )
    parser.add_argument(
        "--results",
        type=pathlib.Path,
        help="directory for one JSON result per case",
    )
    args = parser.parse_args()

    if args.module is not None:
        if args.slot is None:
            parser.error("--slot is required with --module")
        os.environ["PKCS11RS_OASIS_MODULE"] = str(args.module.resolve())
    if args.slot is not None:
        os.environ["PKCS11RS_OASIS_SLOT"] = str(args.slot)
    if args.results is not None:
        os.environ["PKCS11RS_OASIS_RESULTS"] = str(args.results.resolve())

    selected = args.cases or list(TEST_METHODS)
    suite = unittest.TestSuite(
        OasisProfileTests(TEST_METHODS[name]) for name in selected
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
