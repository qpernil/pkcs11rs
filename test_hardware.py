#!/usr/bin/env python3
"""Opt-in smoke tests for live YubiKey/YubiHSM slot discovery."""

from __future__ import annotations

import concurrent.futures
import ctypes
import os
import pathlib
import platform
import subprocess
import threading
import unittest

from test_pkcs11 import CK_BYTE, CK_RV, CK_SLOT_INFO, CK_TOKEN_INFO, CK_ULONG


ROOT = os.path.dirname(os.path.abspath(__file__))
RUN_HARDWARE_TESTS = os.environ.get("PKCS11RS_RUN_HARDWARE_TESTS") == "1"
CKR_OK = 0
CKF_SERIAL_SESSION = 0x00000004
CKU_USER = 1


def hardware_library_path() -> pathlib.Path:
    system = platform.system()
    if system == "Darwin":
        name = "libpkcs11rs.dylib"
    elif system == "Windows":
        name = "pkcs11rs.dll"
    else:
        name = "libpkcs11rs.so"
    return pathlib.Path(ROOT) / "target" / "debug" / name


@unittest.skipUnless(
    RUN_HARDWARE_TESTS,
    "set PKCS11RS_RUN_HARDWARE_TESTS=1 to run live hardware tests",
)
class HardwareDiscoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        subprocess.run(
            ["cargo", "build", "--locked", "--no-default-features"],
            cwd=ROOT,
            check=True,
        )
        cls.lib = ctypes.CDLL(str(hardware_library_path()))
        cls.lib.C_Initialize.argtypes = [ctypes.c_void_p]
        cls.lib.C_Initialize.restype = CK_RV
        cls.lib.C_Finalize.argtypes = [ctypes.c_void_p]
        cls.lib.C_Finalize.restype = CK_RV
        cls.lib.C_GetSlotList.argtypes = [
            CK_BYTE,
            ctypes.POINTER(CK_ULONG),
            ctypes.POINTER(CK_ULONG),
        ]
        cls.lib.C_GetSlotList.restype = CK_RV
        cls.lib.C_GetSlotInfo.argtypes = [
            CK_ULONG,
            ctypes.POINTER(CK_SLOT_INFO),
        ]
        cls.lib.C_GetSlotInfo.restype = CK_RV
        cls.lib.C_GetTokenInfo.argtypes = [
            CK_ULONG,
            ctypes.POINTER(CK_TOKEN_INFO),
        ]
        cls.lib.C_GetTokenInfo.restype = CK_RV
        cls.lib.C_OpenSession.argtypes = [
            CK_ULONG,
            CK_ULONG,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(CK_ULONG),
        ]
        cls.lib.C_OpenSession.restype = CK_RV
        cls.lib.C_CloseSession.argtypes = [CK_ULONG]
        cls.lib.C_CloseSession.restype = CK_RV
        cls.lib.C_Login.argtypes = [
            CK_ULONG,
            CK_ULONG,
            ctypes.POINTER(CK_BYTE),
            CK_ULONG,
        ]
        cls.lib.C_Login.restype = CK_RV
        cls.lib.C_Logout.argtypes = [CK_ULONG]
        cls.lib.C_Logout.restype = CK_RV
        cls.lib.C_GenerateRandom.argtypes = [
            CK_ULONG,
            ctypes.POINTER(CK_BYTE),
            CK_ULONG,
        ]
        cls.lib.C_GenerateRandom.restype = CK_RV

    def tearDown(self) -> None:
        self.lib.C_Finalize(None)

    def test_live_slots_report_metadata(self) -> None:
        self.assertEqual(self.lib.C_Initialize(None), CKR_OK)
        count = CK_ULONG()
        self.assertEqual(self.lib.C_GetSlotList(1, None, ctypes.byref(count)), CKR_OK)
        if count.value == 0:
            self.skipTest("no live YubiKey or YubiHSM was discovered")

        slots = (CK_ULONG * count.value)()
        self.assertEqual(
            self.lib.C_GetSlotList(1, slots, ctypes.byref(count)), CKR_OK
        )
        for index in range(count.value):
            slot_id = slots[index]
            slot_info = CK_SLOT_INFO()
            token_info = CK_TOKEN_INFO()
            self.assertEqual(
                self.lib.C_GetSlotInfo(slot_id, ctypes.byref(slot_info)), CKR_OK
            )
            self.assertEqual(
                self.lib.C_GetTokenInfo(slot_id, ctypes.byref(token_info)), CKR_OK
            )

    def test_two_yubihsms_survive_many_threaded_operations(self) -> None:
        thread_count = 16
        calls_per_thread = 100
        self.assertEqual(self.lib.C_Initialize(None), CKR_OK)

        count = CK_ULONG()
        self.assertEqual(self.lib.C_GetSlotList(1, None, ctypes.byref(count)), CKR_OK)
        slot_ids = (CK_ULONG * count.value)()
        self.assertEqual(
            self.lib.C_GetSlotList(1, slot_ids, ctypes.byref(count)), CKR_OK
        )
        yubihsm_slots = []
        for slot_id in slot_ids:
            slot_info = CK_SLOT_INFO()
            self.assertEqual(
                self.lib.C_GetSlotInfo(slot_id, ctypes.byref(slot_info)), CKR_OK
            )
            description = bytes(slot_info.slotDescription).rstrip(b" ").decode("utf-8")
            if description.startswith("Yubico YubiHSM "):
                yubihsm_slots.append((slot_id, description))
        if len(yubihsm_slots) < 2:
            self.skipTest("fewer than two live YubiHSM slots were discovered")
        yubihsm_slots = yubihsm_slots[:2]

        def open_session(slot_id: int) -> int:
            session = CK_ULONG()
            self.assertEqual(
                self.lib.C_OpenSession(
                    slot_id,
                    CKF_SERIAL_SESSION,
                    None,
                    None,
                    ctypes.byref(session),
                ),
                CKR_OK,
            )
            return session.value

        control_sessions = [
            open_session(slot_id) for slot_id, _description in yubihsm_slots
        ]
        pin = (CK_BYTE * len(b"0001password"))(*b"0001password")
        for session in control_sessions:
            self.assertEqual(
                self.lib.C_Login(session, CKU_USER, pin, len(pin)), CKR_OK
            )

        sessions = [
            (
                thread_index % 2,
                open_session(yubihsm_slots[thread_index % 2][0]),
            )
            for thread_index in range(thread_count)
        ]
        start = threading.Barrier(thread_count)

        def worker(slot_index: int, session: int) -> int:
            start.wait()
            previous = None
            try:
                for _ in range(calls_per_thread):
                    output = (CK_BYTE * 32)()
                    result = self.lib.C_GenerateRandom(
                        session, output, len(output)
                    )
                    if result != CKR_OK:
                        raise AssertionError(
                            f"C_GenerateRandom on {yubihsm_slots[slot_index][1]} "
                            f"returned {result:#x}"
                        )
                    current = bytes(output)
                    if current == previous:
                        raise AssertionError(
                            "YubiHSM returned the same random block twice"
                        )
                    previous = current
                return calls_per_thread
            finally:
                result = self.lib.C_CloseSession(session)
                if result != CKR_OK:
                    raise AssertionError(
                        f"C_CloseSession({session}) returned {result:#x}"
                    )

        try:
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=thread_count
            ) as executor:
                futures = [
                    executor.submit(worker, slot_index, session)
                    for slot_index, session in sessions
                ]
                self.assertEqual(
                    sum(future.result() for future in futures),
                    thread_count * calls_per_thread,
                )
        finally:
            for session in control_sessions:
                self.assertEqual(self.lib.C_Logout(session), CKR_OK)
                self.assertEqual(self.lib.C_CloseSession(session), CKR_OK)


if __name__ == "__main__":
    unittest.main()
