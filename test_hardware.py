#!/usr/bin/env python3
"""Opt-in smoke tests for live YubiKey/YubiHSM slot discovery."""

from __future__ import annotations

import ctypes
import os
import subprocess
import unittest

from test_pkcs11 import CK_BYTE, CK_RV, CK_SLOT_INFO, CK_TOKEN_INFO, CK_ULONG, library_path


ROOT = os.path.dirname(os.path.abspath(__file__))
RUN_HARDWARE_TESTS = os.environ.get("PKCS11RS_RUN_HARDWARE_TESTS") == "1"
CKR_OK = 0


@unittest.skipUnless(
    RUN_HARDWARE_TESTS,
    "set PKCS11RS_RUN_HARDWARE_TESTS=1 to run live hardware tests",
)
class HardwareDiscoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        subprocess.run(
            ["cargo", "build", "--no-default-features"], cwd=ROOT, check=True
        )
        cls.lib = ctypes.CDLL(str(library_path()))
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


if __name__ == "__main__":
    unittest.main()
