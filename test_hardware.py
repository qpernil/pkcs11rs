#!/usr/bin/env python3
"""Opt-in smoke tests for live YubiKey/YubiHSM slot discovery."""

from __future__ import annotations

import concurrent.futures
import ctypes
import hashlib
import json
import os
import pathlib
import platform
import subprocess
import threading
import tempfile
import time
import unittest
import uuid

import test_pkcs11 as abi

from test_pkcs11 import (
    CKA_ALWAYS_AUTHENTICATE,
    CKA_CLASS,
    CKA_DERIVE,
    CKA_EC_POINT,
    CKA_KEY_TYPE,
    CKA_PRIVATE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VERIFY,
    CKK_EC,
    CKM_ECDSA,
    CKO_PRIVATE_KEY,
    CK_ATTRIBUTE,
    CK_BYTE,
    CK_MECHANISM,
    CK_RV,
    CK_SLOT_INFO,
    CK_TOKEN_INFO,
    CK_ULONG,
)


ROOT = os.path.dirname(os.path.abspath(__file__))
RUN_HARDWARE_TESTS = os.environ.get("PKCS11RS_RUN_HARDWARE_TESTS") == "1"
CKR_OK = 0
CKR_SIGNATURE_INVALID = 0xC0
CKR_USER_NOT_LOGGED_IN = 0x101
CKF_SERIAL_SESSION = 0x00000004
CKF_RW_SESSION = 0x00000002
CKU_USER = 1
CKU_CONTEXT_SPECIFIC = 2
CKM_VENDOR_DEFINED = 0x80000000
CKK_VENDOR_DEFINED = 0x80000000
CKA_VENDOR_DEFINED = 0x80000000
CKM_PKCS11RS_PREVIEW_SIGN_KEY_PAIR_GEN = CKM_VENDOR_DEFINED | 0x50530001
CKM_PKCS11RS_PREVIEW_SIGN_DERIVE = CKM_VENDOR_DEFINED | 0x50530002
CKM_PKCS11RS_PREVIEW_SIGN = CKM_VENDOR_DEFINED | 0x50530003
CKM_PKCS11RS_PROJECT_PUBLIC_KEY = CKM_VENDOR_DEFINED | 0x50530004
CKK_PKCS11RS_PREVIEW_SIGN_REGISTRATION = CKK_VENDOR_DEFINED | 0x50530001
CKA_PKCS11RS_PREVIEW_SIGN_REGISTRATION = CKA_VENDOR_DEFINED | 0x50530001
CKA_PKCS11RS_PREVIEW_SIGN_DERIVED_KEY = CKA_VENDOR_DEFINED | 0x50530002


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
            ["cargo", "build", "--locked"],
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
        cls.lib.C_GetMechanismList.argtypes = [
            CK_ULONG,
            ctypes.POINTER(CK_ULONG),
            ctypes.POINTER(CK_ULONG),
        ]
        cls.lib.C_GetMechanismList.restype = CK_RV
        cls.lib.C_GenerateKeyPair.argtypes = [
            CK_ULONG,
            ctypes.POINTER(CK_MECHANISM),
            ctypes.POINTER(CK_ATTRIBUTE),
            CK_ULONG,
            ctypes.POINTER(CK_ATTRIBUTE),
            CK_ULONG,
            ctypes.POINTER(CK_ULONG),
            ctypes.POINTER(CK_ULONG),
        ]
        cls.lib.C_GenerateKeyPair.restype = CK_RV
        cls.lib.C_CreateObject.argtypes = [
            CK_ULONG,
            ctypes.POINTER(CK_ATTRIBUTE),
            CK_ULONG,
            ctypes.POINTER(CK_ULONG),
        ]
        cls.lib.C_CreateObject.restype = CK_RV
        cls.lib.C_DestroyObject.argtypes = [CK_ULONG, CK_ULONG]
        cls.lib.C_DestroyObject.restype = CK_RV
        cls.lib.C_GetAttributeValue.argtypes = [
            CK_ULONG,
            CK_ULONG,
            ctypes.POINTER(CK_ATTRIBUTE),
            CK_ULONG,
        ]
        cls.lib.C_GetAttributeValue.restype = CK_RV
        cls.lib.C_DeriveKey.argtypes = [
            CK_ULONG,
            ctypes.POINTER(CK_MECHANISM),
            CK_ULONG,
            ctypes.POINTER(CK_ATTRIBUTE),
            CK_ULONG,
            ctypes.POINTER(CK_ULONG),
        ]
        cls.lib.C_DeriveKey.restype = CK_RV
        cls.lib.C_SignInit.argtypes = [
            CK_ULONG,
            ctypes.POINTER(CK_MECHANISM),
            CK_ULONG,
        ]
        cls.lib.C_SignInit.restype = CK_RV
        cls.lib.C_Sign.argtypes = [
            CK_ULONG,
            ctypes.POINTER(CK_BYTE),
            CK_ULONG,
            ctypes.POINTER(CK_BYTE),
            ctypes.POINTER(CK_ULONG),
        ]
        cls.lib.C_Sign.restype = CK_RV
        cls.lib.C_VerifyInit.argtypes = [
            CK_ULONG,
            ctypes.POINTER(CK_MECHANISM),
            CK_ULONG,
        ]
        cls.lib.C_VerifyInit.restype = CK_RV
        cls.lib.C_Verify.argtypes = [
            CK_ULONG,
            ctypes.POINTER(CK_BYTE),
            CK_ULONG,
            ctypes.POINTER(CK_BYTE),
            CK_ULONG,
        ]
        cls.lib.C_Verify.restype = CK_RV
        cls.lib.C_GenerateRandom.argtypes = [
            CK_ULONG,
            ctypes.POINTER(CK_BYTE),
            CK_ULONG,
        ]
        cls.lib.C_GenerateRandom.restype = CK_RV

    def tearDown(self) -> None:
        self.lib.C_Finalize(None)

    @staticmethod
    def scalar_attribute(
        attribute_type: int, value: int, value_type: type[ctypes._SimpleCData] = CK_ULONG
    ) -> tuple[CK_ATTRIBUTE, ctypes._SimpleCData]:
        storage = value_type(value)
        attribute = CK_ATTRIBUTE(
            attribute_type,
            ctypes.cast(ctypes.byref(storage), ctypes.c_void_p),
            ctypes.sizeof(storage),
        )
        return attribute, storage

    @staticmethod
    def bytes_attribute(
        attribute_type: int, value: bytes
    ) -> tuple[CK_ATTRIBUTE, ctypes.Array[CK_BYTE]]:
        storage = (CK_BYTE * len(value)).from_buffer_copy(value)
        attribute = CK_ATTRIBUTE(
            attribute_type,
            ctypes.cast(storage, ctypes.c_void_p),
            len(storage),
        )
        return attribute, storage

    def read_attribute(self, session: int, handle: int, attribute_type: int) -> bytes:
        attribute = CK_ATTRIBUTE(attribute_type, None, 0)
        self.assertEqual(
            self.lib.C_GetAttributeValue(
                session, handle, ctypes.byref(attribute), 1
            ),
            CKR_OK,
        )
        value = (CK_BYTE * attribute.ulValueLen)()
        attribute.pValue = ctypes.cast(value, ctypes.c_void_p)
        self.assertEqual(
            self.lib.C_GetAttributeValue(
                session, handle, ctypes.byref(attribute), 1
            ),
            CKR_OK,
        )
        return bytes(value[: attribute.ulValueLen])

    def selected_fido_slot(self) -> tuple[int, str]:
        source = os.environ.get("PKCS11RS_FIDO2_TEST_SOURCE")
        if not source:
            self.skipTest("set PKCS11RS_FIDO2_TEST_SOURCE to the exact test token serial")

        count = CK_ULONG()
        self.assertEqual(
            self.lib.C_GetSlotList(1, None, ctypes.byref(count)), CKR_OK
        )
        slots = (CK_ULONG * count.value)()
        self.assertEqual(
            self.lib.C_GetSlotList(1, slots, ctypes.byref(count)), CKR_OK
        )
        matches: list[tuple[int, str]] = []
        for slot_id in slots:
            slot_info = CK_SLOT_INFO()
            token_info = CK_TOKEN_INFO()
            self.assertEqual(
                self.lib.C_GetSlotInfo(slot_id, ctypes.byref(slot_info)), CKR_OK
            )
            self.assertEqual(
                self.lib.C_GetTokenInfo(slot_id, ctypes.byref(token_info)), CKR_OK
            )
            description = bytes(slot_info.slotDescription).rstrip(b" ").decode("utf-8")
            serial = bytes(token_info.serialNumber).rstrip(b" ").decode("utf-8")
            if serial == source and "FIDO" in description:
                matches.append((slot_id, description))
        self.assertEqual(
            len(matches),
            1,
            f"expected one FIDO slot with serial {source!r}, found {matches!r}",
        )
        return matches[0]

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

    def test_preview_sign_two_key_cycle(self) -> None:
        pin_value = os.environ.get("PKCS11RS_FIDO2_TEST_PIN")
        if pin_value is None:
            self.skipTest("set PKCS11RS_FIDO2_TEST_PIN to enable previewSign")

        self.assertEqual(self.lib.C_Initialize(None), CKR_OK)
        slot_id, description = self.selected_fido_slot()

        mechanism_count = CK_ULONG()
        self.assertEqual(
            self.lib.C_GetMechanismList(
                slot_id, None, ctypes.byref(mechanism_count)
            ),
            CKR_OK,
        )
        mechanisms = (CK_ULONG * mechanism_count.value)()
        self.assertEqual(
            self.lib.C_GetMechanismList(
                slot_id, mechanisms, ctypes.byref(mechanism_count)
            ),
            CKR_OK,
        )
        for required in (
            CKM_PKCS11RS_PREVIEW_SIGN_KEY_PAIR_GEN,
            CKM_PKCS11RS_PREVIEW_SIGN_DERIVE,
            CKM_PKCS11RS_PREVIEW_SIGN,
            CKM_PKCS11RS_PROJECT_PUBLIC_KEY,
        ):
            self.assertIn(required, mechanisms)

        session = CK_ULONG()
        parent_public = CK_ULONG()
        parent_private = CK_ULONG()
        cleanup_handles: list[int] = []
        logged_in = False
        try:
            self.assertEqual(
                self.lib.C_OpenSession(
                    slot_id,
                    CKF_SERIAL_SESSION | CKF_RW_SESSION,
                    None,
                    None,
                    ctypes.byref(session),
                ),
                CKR_OK,
            )
            pin = (CK_BYTE * len(pin_value.encode())).from_buffer_copy(
                pin_value.encode()
            )
            self.assertEqual(
                self.lib.C_Login(session.value, CKU_USER, pin, len(pin)), CKR_OK
            )
            logged_in = True

            mechanism = CK_MECHANISM(
                CKM_PKCS11RS_PREVIEW_SIGN_KEY_PAIR_GEN, None, 0
            )
            public_attributes_with_storage = [
                self.scalar_attribute(CKA_KEY_TYPE, CKK_EC),
                self.scalar_attribute(CKA_TOKEN, 1, CK_BYTE),
            ]
            private_attributes_with_storage = [
                self.scalar_attribute(CKA_KEY_TYPE, CKK_EC),
                self.scalar_attribute(CKA_TOKEN, 1, CK_BYTE),
                self.scalar_attribute(CKA_PRIVATE, 1, CK_BYTE),
            ]
            public_template = (CK_ATTRIBUTE * len(public_attributes_with_storage))(
                *(item[0] for item in public_attributes_with_storage)
            )
            private_template = (CK_ATTRIBUTE * len(private_attributes_with_storage))(
                *(item[0] for item in private_attributes_with_storage)
            )
            print("previewSign registration: touch the selected YubiKey when it flashes", flush=True)
            self.assertEqual(
                self.lib.C_GenerateKeyPair(
                    session.value,
                    ctypes.byref(mechanism),
                    public_template,
                    len(public_template),
                    private_template,
                    len(private_template),
                    ctypes.byref(parent_public),
                    ctypes.byref(parent_private),
                ),
                CKR_OK,
            )

            registration = self.read_attribute(
                session.value,
                parent_private.value,
                CKA_PKCS11RS_PREVIEW_SIGN_REGISTRATION,
            )
            registration_attributes_with_storage = [
                self.scalar_attribute(CKA_CLASS, CKO_PRIVATE_KEY),
                self.scalar_attribute(
                    CKA_KEY_TYPE, CKK_PKCS11RS_PREVIEW_SIGN_REGISTRATION
                ),
                self.scalar_attribute(CKA_TOKEN, 0, CK_BYTE),
                self.scalar_attribute(CKA_PRIVATE, 1, CK_BYTE),
                self.scalar_attribute(CKA_DERIVE, 1, CK_BYTE),
                self.bytes_attribute(
                    CKA_PKCS11RS_PREVIEW_SIGN_REGISTRATION, registration
                ),
            ]
            registration_template = (
                CK_ATTRIBUTE * len(registration_attributes_with_storage)
            )(*(item[0] for item in registration_attributes_with_storage))
            registration_key = CK_ULONG()
            self.assertEqual(
                self.lib.C_CreateObject(
                    session.value,
                    registration_template,
                    len(registration_template),
                    ctypes.byref(registration_key),
                ),
                CKR_OK,
            )
            cleanup_handles.append(registration_key.value)

            digest_bytes = hashlib.sha256(
                b"pkcs11rs previewSign Python hardware cycle"
            ).digest()
            digest = (CK_BYTE * len(digest_bytes)).from_buffer_copy(digest_bytes)
            public_points: list[bytes] = []
            derived_wrappers: list[bytes] = []
            signatures: list[bytes] = []
            projected_keys: list[int] = []

            for context_value in (
                b"pkcs11rs Python previewSign key one",
                b"pkcs11rs Python previewSign key two",
            ):
                context = (CK_BYTE * len(context_value)).from_buffer_copy(context_value)
                derive_mechanism = CK_MECHANISM(
                    CKM_PKCS11RS_PREVIEW_SIGN_DERIVE,
                    ctypes.cast(context, ctypes.c_void_p),
                    len(context),
                )
                derived_attributes_with_storage = [
                    self.scalar_attribute(CKA_CLASS, CKO_PRIVATE_KEY),
                    self.scalar_attribute(CKA_KEY_TYPE, CKK_EC),
                    self.scalar_attribute(CKA_TOKEN, 0, CK_BYTE),
                    self.scalar_attribute(CKA_PRIVATE, 1, CK_BYTE),
                    self.scalar_attribute(CKA_SIGN, 1, CK_BYTE),
                ]
                derived_template = (
                    CK_ATTRIBUTE * len(derived_attributes_with_storage)
                )(*(item[0] for item in derived_attributes_with_storage))
                signing_key = CK_ULONG()
                self.assertEqual(
                    self.lib.C_DeriveKey(
                        session.value,
                        ctypes.byref(derive_mechanism),
                        registration_key.value,
                        derived_template,
                        len(derived_template),
                        ctypes.byref(signing_key),
                    ),
                    CKR_OK,
                )
                self.assertEqual(
                    self.read_attribute(
                        session.value,
                        signing_key.value,
                        CKA_PKCS11RS_PREVIEW_SIGN_REGISTRATION,
                    ),
                    registration,
                )
                derived = self.read_attribute(
                    session.value,
                    signing_key.value,
                    CKA_PKCS11RS_PREVIEW_SIGN_DERIVED_KEY,
                )
                derived_wrappers.append(derived)
                self.assertEqual(
                    self.lib.C_DestroyObject(session.value, signing_key.value),
                    CKR_OK,
                )

                restore_attributes_with_storage = [
                    self.scalar_attribute(CKA_CLASS, CKO_PRIVATE_KEY),
                    self.scalar_attribute(CKA_KEY_TYPE, CKK_EC),
                    self.scalar_attribute(CKA_TOKEN, 0, CK_BYTE),
                    self.scalar_attribute(CKA_PRIVATE, 1, CK_BYTE),
                    self.scalar_attribute(CKA_SIGN, 1, CK_BYTE),
                    self.bytes_attribute(
                        CKA_PKCS11RS_PREVIEW_SIGN_REGISTRATION, registration
                    ),
                    self.bytes_attribute(
                        CKA_PKCS11RS_PREVIEW_SIGN_DERIVED_KEY, derived
                    ),
                ]
                restore_template = (
                    CK_ATTRIBUTE * len(restore_attributes_with_storage)
                )(*(item[0] for item in restore_attributes_with_storage))
                restored_key = CK_ULONG()
                self.assertEqual(
                    self.lib.C_CreateObject(
                        session.value,
                        restore_template,
                        len(restore_template),
                        ctypes.byref(restored_key),
                    ),
                    CKR_OK,
                )
                cleanup_handles.append(restored_key.value)
                self.assertEqual(
                    self.read_attribute(
                        session.value,
                        restored_key.value,
                        CKA_ALWAYS_AUTHENTICATE,
                    ),
                    b"\x01",
                )

                project_mechanism = CK_MECHANISM(
                    CKM_PKCS11RS_PROJECT_PUBLIC_KEY, None, 0
                )
                project_attributes_with_storage = [
                    self.scalar_attribute(CKA_TOKEN, 0, CK_BYTE),
                    self.scalar_attribute(CKA_VERIFY, 1, CK_BYTE),
                ]
                project_template = (
                    CK_ATTRIBUTE * len(project_attributes_with_storage)
                )(*(item[0] for item in project_attributes_with_storage))
                projected_key = CK_ULONG()
                self.assertEqual(
                    self.lib.C_DeriveKey(
                        session.value,
                        ctypes.byref(project_mechanism),
                        restored_key.value,
                        project_template,
                        len(project_template),
                        ctypes.byref(projected_key),
                    ),
                    CKR_OK,
                )
                cleanup_handles.append(projected_key.value)
                projected_keys.append(projected_key.value)
                public_points.append(
                    self.read_attribute(
                        session.value, projected_key.value, CKA_EC_POINT
                    )
                )

                sign_mechanism = CK_MECHANISM(
                    CKM_PKCS11RS_PREVIEW_SIGN, None, 0
                )
                self.assertEqual(
                    self.lib.C_SignInit(
                        session.value,
                        ctypes.byref(sign_mechanism),
                        restored_key.value,
                    ),
                    CKR_OK,
                )
                signature_length = CK_ULONG()
                self.assertEqual(
                    self.lib.C_Sign(
                        session.value,
                        digest,
                        len(digest),
                        None,
                        ctypes.byref(signature_length),
                    ),
                    CKR_USER_NOT_LOGGED_IN,
                )
                self.assertEqual(
                    self.lib.C_Login(
                        session.value,
                        CKU_CONTEXT_SPECIFIC,
                        pin,
                        len(pin),
                    ),
                    CKR_OK,
                )
                print(
                    f"previewSign signature {len(signatures) + 1}/2: "
                    "touch the selected YubiKey when it flashes",
                    flush=True,
                )
                self.assertEqual(
                    self.lib.C_Sign(
                        session.value,
                        digest,
                        len(digest),
                        None,
                        ctypes.byref(signature_length),
                    ),
                    CKR_OK,
                )
                self.assertEqual(signature_length.value, 64)
                signature = (CK_BYTE * signature_length.value)()
                self.assertEqual(
                    self.lib.C_Sign(
                        session.value,
                        digest,
                        len(digest),
                        signature,
                        ctypes.byref(signature_length),
                    ),
                    CKR_OK,
                )
                signatures.append(bytes(signature[: signature_length.value]))

                verify_mechanism = CK_MECHANISM(CKM_ECDSA, None, 0)
                self.assertEqual(
                    self.lib.C_VerifyInit(
                        session.value,
                        ctypes.byref(verify_mechanism),
                        projected_key.value,
                    ),
                    CKR_OK,
                )
                self.assertEqual(
                    self.lib.C_Verify(
                        session.value,
                        digest,
                        len(digest),
                        signature,
                        signature_length.value,
                    ),
                    CKR_OK,
                )

            self.assertNotEqual(derived_wrappers[0], derived_wrappers[1])
            self.assertNotEqual(public_points[0], public_points[1])
            self.assertNotEqual(signatures[0], signatures[1])

            wrong_signature = (CK_BYTE * len(signatures[1])).from_buffer_copy(
                signatures[1]
            )
            verify_mechanism = CK_MECHANISM(CKM_ECDSA, None, 0)
            self.assertEqual(
                self.lib.C_VerifyInit(
                    session.value,
                    ctypes.byref(verify_mechanism),
                    projected_keys[0],
                ),
                CKR_OK,
            )
            self.assertEqual(
                self.lib.C_Verify(
                    session.value,
                    digest,
                    len(digest),
                    wrong_signature,
                    len(wrong_signature),
                ),
                CKR_SIGNATURE_INVALID,
            )

            for handle in reversed(cleanup_handles):
                self.assertEqual(
                    self.lib.C_DestroyObject(session.value, handle), CKR_OK
                )
            cleanup_handles.clear()
            self.assertEqual(self.lib.C_Logout(session.value), CKR_OK)
            logged_in = False
            self.assertEqual(
                self.lib.C_Login(session.value, CKU_USER, pin, len(pin)), CKR_OK
            )
            logged_in = True
            self.assertEqual(
                self.lib.C_DestroyObject(session.value, parent_private.value),
                CKR_OK,
            )
            parent_private.value = 0
            self.assertEqual(
                self.lib.C_DestroyObject(session.value, parent_public.value), CKR_OK
            )
            parent_public.value = 0
            self.assertEqual(self.lib.C_Logout(session.value), CKR_OK)
            logged_in = False
            self.assertEqual(self.lib.C_CloseSession(session.value), CKR_OK)
            session.value = 0
        finally:
            if session.value:
                for handle in reversed(cleanup_handles):
                    self.lib.C_DestroyObject(session.value, handle)
                if parent_private.value:
                    self.lib.C_DestroyObject(session.value, parent_private.value)
                if parent_public.value:
                    self.lib.C_DestroyObject(session.value, parent_public.value)
                if logged_in:
                    self.lib.C_Logout(session.value)
                self.lib.C_CloseSession(session.value)

        print(
            "completed external PKCS #11 previewSign cycle with two distinct keys "
            f"on {description}: registration {len(registration)} bytes, "
            f"derived wrappers {[len(value) for value in derived_wrappers]}, "
            f"signatures {[len(value) for value in signatures]}"
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


@unittest.skipUnless(
    os.environ.get("PKCS11RS_RUN_HEADER_HARDWARE_TESTS") == "1",
    "set PKCS11RS_RUN_HEADER_HARDWARE_TESTS=1 for the explicitly selected extension targets",
)
class HeaderExtensionHardwareTests(abi.HsmAuthExportLifecycleMixin, unittest.TestCase):
    """All header extensions on their production hardware or native backend."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.yubikey = os.environ["PKCS11RS_HEADER_TEST_YUBIKEY"]
        cls.yubihsm = os.environ["PKCS11RS_HEADER_TEST_YUBIHSM"]
        cls.allow_reset = os.environ.get("PKCS11RS_HEADER_TEST_ALLOW_RESET") == "1"
        HardwareDiscoveryTests.setUpClass.__func__(cls)
        raw = cls.lib
        for name, arguments in {
            "C_InitToken": [CK_ULONG, ctypes.POINTER(CK_BYTE), CK_ULONG, ctypes.POINTER(CK_BYTE)],
            "C_InitPIN": [CK_ULONG, ctypes.POINTER(CK_BYTE), CK_ULONG],
        }.items():
            function = getattr(raw, name)
            function.argtypes = arguments
            function.restype = CK_RV
        names = abi.bind_header_extensions(raw)
        cls.results = {name: [] for name in names}
        cls.test_results = {}
        cls.expected_unsupported = {}
        cls.report_path = pathlib.Path(os.environ.get(
            "PKCS11RS_HEADER_TEST_RESULTS", str(pathlib.Path(ROOT) / "target/header-hardware-results.json")))

        class RecordingLibrary:
            def __getattr__(self, name):
                function = getattr(raw, name)
                if name not in cls.results:
                    return function
                def call(*arguments):
                    result = function(*arguments)
                    cls.results[name].append(result.decode() if isinstance(result, bytes) else result)
                    return result
                return call

        cls.lib = RecordingLibrary()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.report_path.parent.mkdir(parents=True, exist_ok=True)
        cls.report_path.write_text(json.dumps({
            "yubikey": cls.yubikey, "yubihsm": cls.yubihsm,
            "module": str(hardware_library_path()),
            "tests": cls.test_results,
            "expected_unsupported": cls.expected_unsupported,
            "complete_header_coverage": all(bool(results) for results in cls.results.values()),
            "functions": {name: {"returns": results, "called": bool(results),
                                  "successful_return": any(value == 0 or isinstance(value, str) for value in results)}
                          for name, results in cls.results.items()},
        }, indent=2) + "\n")
        complete = len(cls.test_results) == len(unittest.defaultTestLoader.getTestCaseNames(cls))
        qualified = all(
            value == "passed" or (
                name == "test_07_hsmauth_credential_password_change_authentication"
                and value == "skipped"
            )
            for name, value in cls.test_results.items()
        )
        if complete and qualified:
            missing = [name for name, results in cls.results.items() if not results]
            if missing:
                raise AssertionError(f"header functions not exercised: {missing}")

    def tearDown(self) -> None:
        self.lib.C_Finalize(None)
        result = self._outcome.result
        failed = any(test is self for test, _ in result.errors + result.failures)
        skipped = any(test is self for test, _ in result.skipped)
        type(self).test_results[self._testMethodName] = "failed" if failed else "skipped" if skipped else "passed"

    @staticmethod
    def buffer(value: bytes):
        return (CK_BYTE * len(value)).from_buffer_copy(value)

    def initialize(self, applications, **extra) -> None:
        self.lib.C_Finalize(None)
        configuration = {
            "version": 1, "hardware": {"discovery": True},
            "slots": {"serials": [self.yubikey, self.yubihsm]},
            "ccid": {"applications": applications, "recreate_sessions": False},
            "software": {"slots": []}, "platform": {"enabled": False},
            "yubihsm": {"urls": [], "recreate_sessions": False},
        }
        configuration.update(extra)
        encoded = ctypes.create_string_buffer(json.dumps(configuration).encode())
        args = abi.CK_C_INITIALIZE_ARGS()
        args.pReserved = ctypes.cast(encoded, ctypes.c_void_p)
        self.assertEqual(self.lib.C_Initialize(ctypes.byref(args)), CKR_OK)

    def open_selected(self, serial: str, description: str):
        deadline = time.monotonic() + 5
        while True:
            count = CK_ULONG()
            self.assertEqual(self.lib.C_GetSlotList(1, None, ctypes.byref(count)), CKR_OK)
            slots = (CK_ULONG * count.value)()
            self.assertEqual(self.lib.C_GetSlotList(1, slots, ctypes.byref(count)), CKR_OK)
            matches = []
            for slot in slots:
                info, details = CK_TOKEN_INFO(), CK_SLOT_INFO()
                self.assertEqual(self.lib.C_GetTokenInfo(slot, ctypes.byref(info)), CKR_OK)
                self.assertEqual(self.lib.C_GetSlotInfo(slot, ctypes.byref(details)), CKR_OK)
                if (not serial or bytes(info.serialNumber).decode().strip() == serial) and description in bytes(details.slotDescription).decode():
                    matches.append(slot)
            if matches or time.monotonic() >= deadline:
                break
            # PC/SC reader visibility can lag after an applet reset/reconnect.
            time.sleep(0.25)
        self.assertEqual(len(matches), 1, f"expected one {description} slot on {serial}")
        session = CK_ULONG()
        self.assertEqual(self.lib.C_OpenSession(matches[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                              None, None, ctypes.byref(session)), CKR_OK)
        return matches[0], session

    def login_hsm(self, session) -> None:
        # The runner targets a disposable HSM explicitly selected by serial.
        pin = self.buffer(b"0001password")
        try:
            self.assertEqual(self.lib.C_Login(session, CKU_USER, pin, len(pin)), CKR_OK)
        finally:
            ctypes.memset(pin, 0, len(pin))

    def diagnostic(self, name, session) -> str:
        function = getattr(self.lib, name)
        length = CK_ULONG()
        self.assertEqual(function(session, None, ctypes.byref(length)), CKR_OK)
        value = (CK_BYTE * (length.value + 1))(*([0xA5] * (length.value + 1)))
        short = CK_ULONG(length.value - 1)
        self.assertEqual(function(session, value, ctypes.byref(short)), abi.CKR_BUFFER_TOO_SMALL)
        self.assertEqual(short.value, length.value)
        self.assertEqual(function(session, value, ctypes.byref(length)), CKR_OK)
        self.assertEqual(value[length.value], 0xA5)
        return bytes(value[:length.value]).decode()

    def test_01_names_diagnostics_and_inventory_refresh(self) -> None:
        for name, known, expected in (
            ("GetMechanismName", abi.CKM_SHA256, b"CKM_SHA256"),
            ("GetReturnValueName", abi.CKR_OK, b"CKR_OK"),
            ("GetObjectClassName", abi.CKO_PRIVATE_KEY, b"CKO_PRIVATE_KEY"),
            ("GetKeyTypeName", abi.CKK_EC, b"CKK_EC"),
            ("GetAttributeTypeName", abi.CKA_LABEL, b"CKA_LABEL"),
            ("GetProfileIdName", 1, b"CKP_BASELINE_PROVIDER"),
        ):
            function = getattr(self.lib, "PKCS11RS_" + name)
            self.assertEqual(function(known), expected)
            self.assertIsNone(function(CK_ULONG(-1).value))
        self.initialize(["hsmauth"])
        slot, session = self.open_selected(self.yubikey, "YubiHSM Auth")
        self.assertEqual(self.diagnostic("PKCS11RS_GetAuthenticatedCredential", session), "none")
        self.assertEqual(self.diagnostic("PKCS11RS_GetSecureChannel", session), "none")
        self.assertEqual(self.lib.PKCS11RS_RefreshTokenObjects(slot), CKR_OK)

    def test_02_hsmauth_export_lifecycle(self) -> None:
        if not self.allow_reset:
            self.skipTest("YubiHSM Auth reset requires PKCS11RS_HEADER_TEST_ALLOW_RESET=1")
        self.initialize(["hsmauth"])
        slot, session = self.open_selected(self.yubikey, "YubiHSM Auth")
        info = CK_TOKEN_INFO()
        self.assertEqual(self.lib.C_GetTokenInfo(slot, ctypes.byref(info)), CKR_OK)
        self.expected_hsmauth_password_change = (CKR_OK if (info.firmwareVersion.major, info.firmwareVersion.minor) >= (5, 80)
                                                else abi.CKR_FUNCTION_NOT_SUPPORTED)
        if self.expected_hsmauth_password_change != CKR_OK:
            type(self).expected_unsupported["PKCS11RS_HsmAuthChangeCredentialPassword"] = {
                "return": abi.CKR_FUNCTION_NOT_SUPPORTED, "required_firmware": "5.8.0",
                "tested_firmware": f"{info.firmwareVersion.major}.{info.firmwareVersion.minor // 10}.{info.firmwareVersion.minor % 10}",
            }
        self.assert_hsmauth_export_lifecycle(session)

    def test_03_security_domain_export_lifecycle(self) -> None:
        if not self.allow_reset:
            self.skipTest("Security Domain qualification requires explicit reset permission")
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
        import datetime

        def initialize_scp(version):
            key = bytes(range(0x40, 0x50)).hex()
            self.initialize(["issuer-sd"], ccid={"applications": ["issuer-sd"], "secure_channel": "scp03", "recreate_sessions": False},
                            scp03={"key_version": version, "enc_key": key, "mac_key": key, "dek_key": key})
            _, session = self.open_selected(self.yubikey, "Issuer")
            pin = self.buffer(b"")
            self.assertEqual(self.lib.C_Login(session, CKU_USER, pin, 0), CKR_OK)
            self.assertEqual(self.diagnostic("PKCS11RS_GetSecureChannel", session), "scp03")
            return session

        session = initialize_scp(255)
        key = self.buffer(bytes(range(0x40, 0x50)))
        keys = abi.PKCS11RS_SCP03_KEY_SET(key, 16, key, 16, key, 16)
        recovery_path = self.report_path.with_name("header-test-scp03-recovery.json")
        recovery_path.write_text(json.dumps({"version": 1, "slots": {"serials": [self.yubikey]},
            "ccid": {"applications": ["issuer-sd"], "secure_channel": "scp03"},
            "scp03": {"key_version": 126, "enc_key": bytes(key).hex(), "mac_key": bytes(key).hex(), "dek_key": bytes(key).hex()}}))
        try:
            self.assertEqual(self.lib.PKCS11RS_SecurityDomainPutScp03KeySet(session, 126, 0, ctypes.byref(keys)), CKR_OK)
            session = initialize_scp(126)
            length = CK_ULONG()
            self.assertEqual(self.lib.PKCS11RS_SecurityDomainGenerateScp11Key(session, 0x13, 127, 0, 0, None, ctypes.byref(length)), CKR_OK)
            public = (CK_BYTE * length.value)()
            self.assertEqual(self.lib.PKCS11RS_SecurityDomainGenerateScp11Key(session, 0x13, 127, 0, 0, public, ctypes.byref(length)), CKR_OK)
            subject_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes(public))
            ca_key = ec.generate_private_key(ec.SECP256R1())
            ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pkcs11rs hardware test CA")])
            now = datetime.datetime.now(datetime.timezone.utc)
            def certificate(subject, public_key, serial, ca):
                return (x509.CertificateBuilder().subject_name(subject).issuer_name(ca_name)
                        .public_key(public_key).serial_number(serial)
                        .not_valid_before(now - datetime.timedelta(days=1))
                        .not_valid_after(now + datetime.timedelta(days=1))
                        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
                        .sign(ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER))
            root = self.buffer(certificate(ca_name, ca_key.public_key(), 1, True))
            leaf = self.buffer(certificate(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pkcs11rs card test")]), subject_key, 2, False))
            chain = (abi.PKCS11RS_BYTE_BUFFER * 2)(abi.PKCS11RS_BYTE_BUFFER(root, len(root)), abi.PKCS11RS_BYTE_BUFFER(leaf, len(leaf)))
            self.assertEqual(self.lib.PKCS11RS_SecurityDomainStoreScp11CertificateChain(session, 0x13, 127, chain, 2), CKR_OK)
            self.assertEqual(self.lib.PKCS11RS_SecurityDomainDeleteScp11Key(session, 0x13, 127, 1), CKR_OK)
            private = self.buffer(ca_key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            try:
                self.assertEqual(self.lib.PKCS11RS_SecurityDomainPutScp11PrivateKey(session, 0x11, 121, 0, private, len(private)), CKR_OK)
            finally:
                ctypes.memset(private, 0, len(private))
            identifier = self.buffer(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()).digest)
            self.assertEqual(self.lib.PKCS11RS_SecurityDomainStoreScp11CaIssuer(session, 0x11, 121, identifier, len(identifier)), CKR_OK)
            serial = self.buffer(b"\x02")
            serials = (abi.PKCS11RS_BYTE_BUFFER * 1)(abi.PKCS11RS_BYTE_BUFFER(serial, len(serial)))
            self.assertEqual(self.lib.PKCS11RS_SecurityDomainDeleteScp11Key(session, 0x11, 121, 1), CKR_OK)
            public_import = self.buffer(ca_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
            self.assertEqual(self.lib.PKCS11RS_SecurityDomainPutScp11PublicKey(session, 0x20, 122, 0, public_import, len(public_import)), CKR_OK)
            self.assertEqual(self.lib.PKCS11RS_SecurityDomainSetScp11Allowlist(session, 0x20, 122, serials, 1), CKR_OK)
            self.assertEqual(self.lib.PKCS11RS_SecurityDomainSetScp11Allowlist(session, 0x20, 122, None, 0), CKR_OK)
            self.assertEqual(self.lib.PKCS11RS_SecurityDomainDeleteScp11Key(session, 0x20, 122, 1), CKR_OK)
            self.assertEqual(self.lib.PKCS11RS_SecurityDomainDeleteScp03KeySet(session, 126, 1), CKR_OK)
        finally:
            self.lib.C_Finalize(None)
            subprocess.run(["ykman", "--device", self.yubikey, "sd", "reset", "--force"], check=True)
            recovery_path.unlink(missing_ok=True)

    def test_07_hsmauth_credential_password_change_authentication(self) -> None:
        """Change one disposable credential and authenticate with both passwords."""
        self.initialize(["hsmauth"])
        slot, session = self.open_selected(self.yubikey, "YubiHSM Auth")
        info = CK_TOKEN_INFO()
        self.assertEqual(self.lib.C_GetTokenInfo(slot, ctypes.byref(info)), CKR_OK)
        if (info.firmwareVersion.major, info.firmwareVersion.minor) < (5, 80):
            self.skipTest("positive credential-password change requires firmware 5.8.0")
        _, hsm_session = self.open_selected(self.yubihsm, "YubiHSM ")
        label_bytes = ("pkcs11rs-password-" + uuid.uuid4().hex[:12]).encode()
        label = self.buffer(label_bytes)
        derivation = self.buffer(b"password")  # Factory HSM authentication key 0001.
        old, new = self.buffer(b"old-test-access"), self.buffer(b"new-test-access")
        created = False

        def login_management():
            if os.environ.get("PKCS11RS_HEADER_TEST_HSMAUTH_FACTORY_MANAGEMENT") == "1":
                factory = self.buffer(b"00000000000000000000000000000000")
                try:
                    self.assertEqual(self.lib.C_Login(session, abi.CKU_SO, factory, len(factory)), CKR_OK)
                finally:
                    ctypes.memset(factory, 0, len(factory))
            else:
                self.assertEqual(self.lib.C_Login(session, abi.CKU_SO, None, 0), CKR_OK)

        def authenticate(password, expected):
            pin = self.buffer(b":0001" + label_bytes + b"@" + self.yubikey.encode() + b":" + bytes(password))
            try:
                self.assertEqual(self.lib.C_Login(hsm_session, CKU_USER, pin, len(pin)), expected)
                if expected == CKR_OK:
                    self.assertEqual(self.diagnostic("PKCS11RS_GetSecureChannel", hsm_session), "scp03")
                    self.assertEqual(self.lib.C_Logout(hsm_session), CKR_OK)
            finally:
                ctypes.memset(pin, 0, len(pin))

        try:
            # Fresh pinentry by default; the public factory key is an explicit opt-in.
            login_management()
            self.assertEqual(self.lib.PKCS11RS_HsmAuthPutDerivedSymmetricCredential(
                session, label, len(label), derivation, len(derivation), old, len(old), 0), CKR_OK)
            created = True
            authenticate(old, CKR_OK)
            self.assertEqual(self.lib.PKCS11RS_HsmAuthChangeCredentialPassword(
                session, label, len(label), new, len(new)), CKR_OK)
            authenticate(old, abi.CKR_PIN_INCORRECT)
            authenticate(new, CKR_OK)
        finally:
            try:
                self.lib.C_Logout(hsm_session)
                if created:
                    result = self.lib.PKCS11RS_HsmAuthDeleteCredential(session, label, len(label))
                    if result == abi.CKR_USER_NOT_LOGGED_IN:
                        login_management()
                        result = self.lib.PKCS11RS_HsmAuthDeleteCredential(session, label, len(label))
                    self.assertEqual(result, CKR_OK, f"failed to remove disposable credential {label_bytes.decode()}")
            finally:
                for value in (derivation, old, new):
                    ctypes.memset(value, 0, len(value))
                self.lib.C_Logout(session)
                self.lib.C_CloseSession(hsm_session)
                self.lib.C_CloseSession(session)

    def test_04_yubihsm_enrollment_exports_validate_factory_attestation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pkcs11rs-hardware-trust-") as directory:
            self.initialize(["hsmauth"], yubihsm={"urls": [], "recreate_sessions": False,
                            "device_trust_prefix": directory + os.sep})
            _, session = self.open_selected(self.yubihsm, "YubiHSM ")
            self.login_hsm(session)
            fingerprints = []
            for name, extra in (
                ("PKCS11RS_YubiHsmEnrollDeviceAttestation", [0]),
                ("PKCS11RS_YubiHsmEnrollDeviceYubicoAttestation", []),
                ("PKCS11RS_YubiHsmEnrollDevicePublicKey", []),
            ):
                function = getattr(self.lib, name)
                length = CK_ULONG()
                self.assertEqual(function(session, *extra, None, ctypes.byref(length)), CKR_OK)
                self.assertEqual(length.value, 32)
                fingerprint = (CK_BYTE * 32)()
                self.assertEqual(function(session, *extra, fingerprint, ctypes.byref(length)), CKR_OK)
                fingerprints.append(bytes(fingerprint))
                entry = pathlib.Path(directory, bytes(fingerprint).hex() + ".cbor")
                self.assertTrue(entry.is_file())
                self.assertTrue(entry.read_bytes())
            self.assertEqual(fingerprints[0], fingerprints[1])
            self.assertEqual(fingerprints[1], fingerprints[2])
            self.assertEqual(self.diagnostic("PKCS11RS_GetSecureChannel", session), "scp03")

    def test_05_native_platform_lifecycle_and_hsm_provisioning_exports(self) -> None:
        driver = os.environ.get("PKCS11RS_HEADER_TEST_PLATFORM_DRIVER")
        if driver:
            module = os.environ.get("PKCS11RS_HEADER_TEST_PLATFORM_MODULE", str(hardware_library_path()))
            completed = subprocess.run([driver, module, self.yubihsm, "7e50"], capture_output=True, text=True)
            for line in completed.stdout.splitlines():
                name, _, result = line.partition(" ")
                if name in self.results and result.isdigit():
                    self.results[name].append(int(result))
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            return
        self.initialize(["hsmauth"])
        _, session = self.open_selected(self.yubihsm, "YubiHSM ")
        self.login_hsm(session)
        name = self.buffer(("pkcs11rs-header-" + uuid.uuid4().hex).encode())
        public = (CK_BYTE * 65)()
        length = CK_ULONG(65)
        generated = False
        provisioned = False
        authkey_id = 0x7E50
        try:
            self.assertEqual(self.lib.PKCS11RS_PlatformCredentialGenerate(name, len(name), public, ctypes.byref(length)), CKR_OK)
            generated = True
            read = (CK_BYTE * 65)()
            self.assertEqual(self.lib.PKCS11RS_PlatformCredentialGetPublicKey(name, len(name), read, ctypes.byref(length)), CKR_OK)
            self.assertEqual(bytes(read), bytes(public))
            count = CK_ULONG()
            self.assertEqual(self.lib.PKCS11RS_PlatformCredentialList(None, ctypes.byref(count)), CKR_OK)
            entries = (abi.PKCS11RS_PLATFORM_CREDENTIAL_INFO * count.value)()
            self.assertEqual(self.lib.PKCS11RS_PlatformCredentialList(entries, ctypes.byref(count)), CKR_OK)
            self.assertTrue(any(bytes(entry.name[:entry.ulNameLen]) == bytes(name) for entry in entries))
            label = self.buffer(b"pkcs11rs header test")
            capabilities = self.buffer(bytes(8))
            result = CK_ULONG()
            for expected in (1, 2):
                self.assertEqual(self.lib.PKCS11RS_YubiHsmProvisionPlatformCredential(
                    session, name, len(name), authkey_id, label, len(label), 0xffff,
                    capabilities, 8, capabilities, 8, ctypes.byref(result)), CKR_OK)
                provisioned = True
                self.assertEqual(result.value, expected)
            self.assertEqual(self.lib.PKCS11RS_YubiHsmUnprovisionPlatformCredential(session, name, len(name), authkey_id), CKR_OK)
            provisioned = False
            self.assertEqual(self.lib.PKCS11RS_YubiHsmUnprovisionPlatformCredential(session, name, len(name), authkey_id), CKR_OK)
            self.assertEqual(self.lib.PKCS11RS_PlatformCredentialDelete(name, len(name)), CKR_OK)
            generated = False
        finally:
            if provisioned:
                self.assertEqual(self.lib.PKCS11RS_YubiHsmUnprovisionPlatformCredential(session, name, len(name), authkey_id), CKR_OK)
            if generated:
                self.assertEqual(self.lib.PKCS11RS_PlatformCredentialDelete(name, len(name)), CKR_OK)

    def test_06_software_private_key_export_on_its_supported_backend(self) -> None:
        storage = tempfile.TemporaryDirectory(prefix="pkcs11rs-header-export-")
        self.addCleanup(storage.cleanup)
        self.initialize(["hsmauth"], software={"slots": [{"name": "header-export"}]},
                        slots={"serials": [self.yubikey, self.yubihsm, "0"]}, storage={"tokens": storage.name})
        slot, session = self.open_selected("", "pkcs11rs software slot: header-export")
        self.assertEqual(self.lib.C_CloseSession(session), CKR_OK)
        so_pin = self.buffer(b"disposable SO password")
        label = self.buffer(b"header export".ljust(32))
        self.assertEqual(self.lib.C_InitToken(slot, so_pin, len(so_pin), label), CKR_OK)
        _, session = self.open_selected("", "pkcs11rs software slot: header-export")
        user_pin = self.buffer(b"disposable USER password")
        try:
            self.assertEqual(self.lib.C_Login(session, abi.CKU_SO, so_pin, len(so_pin)), CKR_OK)
            self.assertEqual(self.lib.C_InitPIN(session, user_pin, len(user_pin)), CKR_OK)
            self.assertEqual(self.lib.C_Logout(session), CKR_OK)
            self.assertEqual(self.lib.C_Login(session, CKU_USER, user_pin, len(user_pin)), CKR_OK)
        finally:
            ctypes.memset(so_pin, 0, len(so_pin))
            ctypes.memset(user_pin, 0, len(user_pin))
        fields = [HardwareDiscoveryTests.scalar_attribute(abi.CKA_CLASS, abi.CKO_PRIVATE_KEY),
                  HardwareDiscoveryTests.scalar_attribute(abi.CKA_KEY_TYPE, abi.CKK_EC),
                  HardwareDiscoveryTests.scalar_attribute(abi.CKA_TOKEN, 0, CK_BYTE),
                  HardwareDiscoveryTests.scalar_attribute(abi.CKA_EXTRACTABLE, 1, CK_BYTE),
                  HardwareDiscoveryTests.scalar_attribute(abi.CKA_SENSITIVE, 0, CK_BYTE),
                  HardwareDiscoveryTests.bytes_attribute(abi.CKA_EC_PARAMS, bytes.fromhex("06082a8648ce3d030107")),
                  HardwareDiscoveryTests.bytes_attribute(abi.CKA_VALUE, bytes(31) + b"\x01")]
        template = (CK_ATTRIBUTE * len(fields))(*(attribute for attribute, _ in fields))
        key = CK_ULONG()
        self.assertEqual(self.lib.C_CreateObject(session, template, len(template), ctypes.byref(key)), CKR_OK)
        password = self.buffer(b"disposable export password")
        try:
            length = CK_ULONG()
            self.assertEqual(self.lib.PKCS11RS_SoftwareExportPrivateKey(session, key, password, len(password), None, ctypes.byref(length)), CKR_OK)
            encrypted = (CK_BYTE * length.value)()
            self.assertEqual(self.lib.PKCS11RS_SoftwareExportPrivateKey(session, key, password, len(password), encrypted, ctypes.byref(length)), CKR_OK)
            from cryptography.hazmat.primitives import serialization
            restored = serialization.load_der_private_key(bytes(encrypted), bytes(password))
            self.assertEqual(restored.private_numbers().private_value, 1)
        finally:
            ctypes.memset(password, 0, len(password))
            self.assertEqual(self.lib.C_DestroyObject(session, key), CKR_OK)


if __name__ == "__main__":
    unittest.main()
