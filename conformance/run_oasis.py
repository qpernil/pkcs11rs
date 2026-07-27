#!/usr/bin/env python3
"""Run selected OASIS PKCS #11 v3.2 mandatory profile cases."""

from __future__ import annotations

import argparse
import ctypes
import os
import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import test_pkcs11 as p11  # noqa: E402

from conformance.test_oasis import OasisProfileTests, _bind_library  # noqa: E402


TEST_METHODS = {
    "BL-M-1-32": "test_BL_M_1_32",
    "EXT-M-1-32": "test_EXT_M_1_32",
    "AUTH-M-1-32": "test_AUTH_M_1_32",
    "CERT-M-1-32": "test_CERT_M_1_32",
}

CASE_PROFILES = {
    "BL-M-1-32": p11.CKP_BASELINE_PROVIDER,
    "EXT-M-1-32": p11.CKP_EXTENDED_PROVIDER,
    "AUTH-M-1-32": p11.CKP_AUTHENTICATION_TOKEN,
    "CERT-M-1-32": p11.CKP_PUBLIC_CERTIFICATES_TOKEN,
}

ABI_QUALIFICATION_CASES = {
    p11.ABI_TEST_SLOT_ID: {"BL-M-1-32"},
    p11.ABI_TEST_PIV_SLOT_ID: {"BL-M-1-32"},
    p11.ABI_TEST_SCP03_SLOT_ID: {"BL-M-1-32"},
    p11.ABI_TEST_YUBIHSM_SLOT_ID: {
        "BL-M-1-32",
        "AUTH-M-1-32",
        "CERT-M-1-32",
    },
    p11.ABI_TEST_SCP11_SLOT_ID: {"BL-M-1-32"},
}


def _require_ok(operation: str, rv: int) -> None:
    if rv != p11.CKR_OK:
        raise RuntimeError(f"{operation} failed with CK_RV 0x{rv:08x}")


def _read_profile_id(
    lib: ctypes.CDLL, session: int, handle: int
) -> int:
    attribute = p11.CK_ATTRIBUTE(p11.CKA_PROFILE_ID, None, 0)
    _require_ok(
        "C_GetAttributeValue(CKA_PROFILE_ID length)",
        lib.C_GetAttributeValue(
            session, handle, ctypes.byref(attribute), 1
        ),
    )
    value = (p11.CK_BYTE * attribute.ulValueLen)()
    attribute.pValue = ctypes.cast(value, p11.CK_VOID_PTR)
    _require_ok(
        "C_GetAttributeValue(CKA_PROFILE_ID)",
        lib.C_GetAttributeValue(
            session, handle, ctypes.byref(attribute), 1
        ),
    )
    return int.from_bytes(bytes(value), byteorder=sys.byteorder)


def _advertised_profiles(
    module: pathlib.Path | None, requested_slot: int | None
) -> dict[int, set[int]]:
    lib = (
        ctypes.CDLL(str(module.resolve()))
        if module is not None
        else p11.load_library()
    )
    _bind_library(lib)
    lib.C_Finalize(None)
    _require_ok("C_Initialize", lib.C_Initialize(None))
    try:
        if requested_slot is None:
            count = p11.CK_ULONG()
            _require_ok(
                "C_GetSlotList(count)",
                lib.C_GetSlotList(1, None, ctypes.byref(count)),
            )
            slots = (p11.CK_ULONG * count.value)()
            _require_ok(
                "C_GetSlotList",
                lib.C_GetSlotList(1, slots, ctypes.byref(count)),
            )
            slot_ids = list(slots[: count.value])
        else:
            slot_ids = [requested_slot]

        result: dict[int, set[int]] = {}
        for slot_id in slot_ids:
            session = p11.CK_ULONG()
            _require_ok(
                f"C_OpenSession(slot {slot_id})",
                lib.C_OpenSession(
                    slot_id,
                    p11.CKF_SERIAL_SESSION,
                    None,
                    None,
                    ctypes.byref(session),
                ),
            )
            try:
                object_class = p11.CK_ULONG(p11.CKO_PROFILE)
                template = p11.CK_ATTRIBUTE(
                    p11.CKA_CLASS,
                    ctypes.cast(ctypes.byref(object_class), p11.CK_VOID_PTR),
                    ctypes.sizeof(object_class),
                )
                _require_ok(
                    "C_FindObjectsInit(CKO_PROFILE)",
                    lib.C_FindObjectsInit(
                        session.value, ctypes.byref(template), 1
                    ),
                )
                handles = (p11.CK_ULONG * 16)()
                found = p11.CK_ULONG()
                _require_ok(
                    "C_FindObjects(CKO_PROFILE)",
                    lib.C_FindObjects(
                        session.value,
                        handles,
                        len(handles),
                        ctypes.byref(found),
                    ),
                )
                _require_ok(
                    "C_FindObjectsFinal",
                    lib.C_FindObjectsFinal(session.value),
                )
                result[slot_id] = {
                    _read_profile_id(lib, session.value, handle)
                    for handle in handles[: found.value]
                }
            finally:
                lib.C_CloseSession(session.value)
        return result
    finally:
        lib.C_Finalize(None)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Execute the final OASIS PKCS #11 v3.2 mandatory provider "
            "profile XML cases advertised by each selected slot. Without "
            "--module, the deterministic ABI test backend is built and used."
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
        help="slot ID to qualify (default: every present slot)",
    )
    parser.add_argument(
        "--case",
        action="append",
        choices=tuple(TEST_METHODS),
        dest="cases",
        help="case to execute when its profile is advertised; repeat as needed",
    )
    parser.add_argument(
        "--results",
        type=pathlib.Path,
        help="directory for one JSON result per case",
    )
    args = parser.parse_args()

    if args.module is not None:
        os.environ["PKCS11RS_OASIS_MODULE"] = str(args.module.resolve())
    if args.results is not None:
        os.environ["PKCS11RS_OASIS_RESULTS"] = str(args.results.resolve())

    advertised = _advertised_profiles(args.module, args.slot)
    if not advertised:
        parser.error("the module has no present slots")
    os.environ["PKCS11RS_OASIS_SLOT"] = str(next(iter(advertised)))
    selected = args.cases or list(TEST_METHODS)
    tests = []
    multiple_slots = len(advertised) > 1
    for slot_id, profile_ids in advertised.items():
        for name in selected:
            if CASE_PROFILES[name] not in profile_ids:
                continue
            if (
                args.module is None
                and name not in ABI_QUALIFICATION_CASES.get(slot_id, set())
            ):
                continue
            test = OasisProfileTests(TEST_METHODS[name])
            test.slot_id = slot_id
            if args.module is None:
                test.pin = (
                    b"123456"
                    if slot_id == p11.ABI_TEST_PIV_SLOT_ID
                    else (
                        b"0001password"
                        if slot_id == p11.ABI_TEST_YUBIHSM_SLOT_ID
                        else b"1234"
                    )
                )
            if multiple_slots:
                test.result_suffix = f"-slot-{slot_id}"
            tests.append(test)
    if not tests:
        parser.error("none of the selected cases are advertised by the selected slots")
    suite = unittest.TestSuite(tests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
