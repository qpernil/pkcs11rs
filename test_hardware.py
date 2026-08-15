#!/usr/bin/env python3
"""Opt-in smoke tests for live YubiKey/YubiHSM slot discovery."""

from __future__ import annotations

import concurrent.futures
import ctypes
import hashlib
import os
import pathlib
import platform
import subprocess
import threading
import unittest

from test_pkcs11 import (
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
CKF_SERIAL_SESSION = 0x00000004
CKF_RW_SESSION = 0x00000002
CKU_USER = 1
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


if __name__ == "__main__":
    unittest.main()
