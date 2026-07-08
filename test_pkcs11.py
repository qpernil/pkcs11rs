#!/usr/bin/env python3
"""ctypes smoke tests for the pkcs11rs shared library."""

from __future__ import annotations

import ctypes
import pathlib
import platform
import subprocess
import unittest


ROOT = pathlib.Path(__file__).resolve().parent
CKR_OK = 0
CKR_SLOT_ID_INVALID = 3
CKR_BUFFER_TOO_SMALL = 0x150
CKR_ARGUMENTS_BAD = 7
CKR_FUNCTION_NOT_SUPPORTED = 0x54
CKR_SESSION_HANDLE_INVALID = 0xB3
CKR_CRYPTOKI_NOT_INITIALIZED = 0x190
CKM_RSA_PKCS = 0x00000001


def library_path() -> pathlib.Path:
    system = platform.system()
    if system == "Darwin":
        name = "libpkcs11rs.dylib"
    elif system == "Windows":
        name = "pkcs11rs.dll"
    else:
        name = "libpkcs11rs.so"
    return ROOT / "target" / "debug" / name


def load_library() -> ctypes.CDLL:
    path = library_path()
    subprocess.run(["cargo", "build"], cwd=ROOT, check=True)
    return ctypes.CDLL(str(path))


CK_BYTE = ctypes.c_ubyte
CK_ULONG = ctypes.c_ulong
CK_RV = CK_ULONG
CK_FLAGS = CK_ULONG
CK_VOID_PTR = ctypes.c_void_p


class CK_VERSION(ctypes.Structure):
    _fields_ = [
        ("major", CK_BYTE),
        ("minor", CK_BYTE),
    ]


class CK_INFO(ctypes.Structure):
    _fields_ = [
        ("cryptokiVersion", CK_VERSION),
        ("manufacturerID", CK_BYTE * 32),
        ("flags", CK_FLAGS),
        ("libraryDescription", CK_BYTE * 32),
        ("libraryVersion", CK_VERSION),
    ]


class CK_SLOT_INFO(ctypes.Structure):
    _fields_ = [
        ("slotDescription", CK_BYTE * 64),
        ("manufacturerID", CK_BYTE * 32),
        ("flags", CK_FLAGS),
        ("hardwareVersion", CK_VERSION),
        ("firmwareVersion", CK_VERSION),
    ]


class CK_TOKEN_INFO(ctypes.Structure):
    _fields_ = [
        ("label", CK_BYTE * 32),
        ("manufacturerID", CK_BYTE * 32),
        ("model", CK_BYTE * 16),
        ("serialNumber", CK_BYTE * 16),
        ("flags", CK_FLAGS),
        ("ulMaxSessionCount", CK_ULONG),
        ("ulSessionCount", CK_ULONG),
        ("ulMaxRwSessionCount", CK_ULONG),
        ("ulRwSessionCount", CK_ULONG),
        ("ulMaxPinLen", CK_ULONG),
        ("ulMinPinLen", CK_ULONG),
        ("ulTotalPublicMemory", CK_ULONG),
        ("ulFreePublicMemory", CK_ULONG),
        ("ulTotalPrivateMemory", CK_ULONG),
        ("ulFreePrivateMemory", CK_ULONG),
        ("hardwareVersion", CK_VERSION),
        ("firmwareVersion", CK_VERSION),
        ("utcTime", CK_BYTE * 16),
    ]


class CK_SESSION_INFO(ctypes.Structure):
    _fields_ = [
        ("slotID", CK_ULONG),
        ("state", CK_ULONG),
        ("flags", CK_FLAGS),
        ("ulDeviceError", CK_ULONG),
    ]


class CK_ATTRIBUTE(ctypes.Structure):
    _fields_ = [
        ("type_", CK_ULONG),
        ("pValue", CK_VOID_PTR),
        ("ulValueLen", CK_ULONG),
    ]


class CK_DATE(ctypes.Structure):
    _fields_ = [
        ("year", CK_BYTE * 4),
        ("month", CK_BYTE * 2),
        ("day", CK_BYTE * 2),
    ]


class CK_MECHANISM(ctypes.Structure):
    _fields_ = [
        ("mechanism", CK_ULONG),
        ("pParameter", CK_VOID_PTR),
        ("ulParameterLen", CK_ULONG),
    ]


class CK_MECHANISM_INFO(ctypes.Structure):
    _fields_ = [
        ("ulMinKeySize", CK_ULONG),
        ("ulMaxKeySize", CK_ULONG),
        ("flags", CK_FLAGS),
    ]


class CK_ECDH1_DERIVE_PARAMS(ctypes.Structure):
    _fields_ = [
        ("kdf", CK_ULONG),
        ("ulSharedDataLen", CK_ULONG),
        ("pSharedData", ctypes.POINTER(CK_BYTE)),
        ("ulPublicDataLen", CK_ULONG),
        ("pPublicData", ctypes.POINTER(CK_BYTE)),
    ]


class CK_RSA_PKCS_OAEP_PARAMS(ctypes.Structure):
    _fields_ = [
        ("hashAlg", CK_ULONG),
        ("mgf", CK_ULONG),
        ("source", CK_ULONG),
        ("pSourceData", CK_VOID_PTR),
        ("ulSourceDataLen", CK_ULONG),
    ]


class CK_RSA_PKCS_PSS_PARAMS(ctypes.Structure):
    _fields_ = [
        ("hashAlg", CK_ULONG),
        ("mgf", CK_ULONG),
        ("sLen", CK_ULONG),
    ]


class CK_C_INITIALIZE_ARGS(ctypes.Structure):
    _fields_ = [
        ("CreateMutex", ctypes.c_void_p),
        ("DestroyMutex", ctypes.c_void_p),
        ("LockMutex", ctypes.c_void_p),
        ("UnlockMutex", ctypes.c_void_p),
        ("flags", CK_FLAGS),
        ("pReserved", ctypes.c_void_p),
    ]


class CK_INTERFACE(ctypes.Structure):
    _fields_ = [
        ("pInterfaceName", ctypes.c_void_p),
        ("pFunctionList", ctypes.c_void_p),
        ("flags", CK_FLAGS),
    ]


LEGACY_FUNCTIONS = [
    "C_Initialize",
    "C_Finalize",
    "C_GetInfo",
    "C_GetFunctionList",
    "C_GetSlotList",
    "C_GetSlotInfo",
    "C_GetTokenInfo",
    "C_GetMechanismList",
    "C_GetMechanismInfo",
    "C_InitToken",
    "C_InitPIN",
    "C_SetPIN",
    "C_OpenSession",
    "C_CloseSession",
    "C_CloseAllSessions",
    "C_GetSessionInfo",
    "C_GetOperationState",
    "C_SetOperationState",
    "C_Login",
    "C_Logout",
    "C_CreateObject",
    "C_CopyObject",
    "C_DestroyObject",
    "C_GetObjectSize",
    "C_GetAttributeValue",
    "C_SetAttributeValue",
    "C_FindObjectsInit",
    "C_FindObjects",
    "C_FindObjectsFinal",
    "C_EncryptInit",
    "C_Encrypt",
    "C_EncryptUpdate",
    "C_EncryptFinal",
    "C_DecryptInit",
    "C_Decrypt",
    "C_DecryptUpdate",
    "C_DecryptFinal",
    "C_DigestInit",
    "C_Digest",
    "C_DigestUpdate",
    "C_DigestKey",
    "C_DigestFinal",
    "C_SignInit",
    "C_Sign",
    "C_SignUpdate",
    "C_SignFinal",
    "C_SignRecoverInit",
    "C_SignRecover",
    "C_VerifyInit",
    "C_Verify",
    "C_VerifyUpdate",
    "C_VerifyFinal",
    "C_VerifyRecoverInit",
    "C_VerifyRecover",
    "C_DigestEncryptUpdate",
    "C_DecryptDigestUpdate",
    "C_SignEncryptUpdate",
    "C_DecryptVerifyUpdate",
    "C_GenerateKey",
    "C_GenerateKeyPair",
    "C_WrapKey",
    "C_UnwrapKey",
    "C_DeriveKey",
    "C_SeedRandom",
    "C_GenerateRandom",
    "C_GetFunctionStatus",
    "C_CancelFunction",
    "C_WaitForSlotEvent",
]

V3_0_FUNCTIONS = [
    "C_GetInterfaceList",
    "C_GetInterface",
    "C_LoginUser",
    "C_SessionCancel",
    "C_MessageEncryptInit",
    "C_EncryptMessage",
    "C_EncryptMessageBegin",
    "C_EncryptMessageNext",
    "C_MessageEncryptFinal",
    "C_MessageDecryptInit",
    "C_DecryptMessage",
    "C_DecryptMessageBegin",
    "C_DecryptMessageNext",
    "C_MessageDecryptFinal",
    "C_MessageSignInit",
    "C_SignMessage",
    "C_SignMessageBegin",
    "C_SignMessageNext",
    "C_MessageSignFinal",
    "C_MessageVerifyInit",
    "C_VerifyMessage",
    "C_VerifyMessageBegin",
    "C_VerifyMessageNext",
    "C_MessageVerifyFinal",
]

V3_2_FUNCTIONS = [
    "C_EncapsulateKey",
    "C_DecapsulateKey",
    "C_VerifySignatureInit",
    "C_VerifySignature",
    "C_VerifySignatureUpdate",
    "C_VerifySignatureFinal",
    "C_GetSessionValidationFlags",
    "C_AsyncComplete",
    "C_AsyncGetID",
    "C_AsyncJoin",
    "C_WrapKeyAuthenticated",
    "C_UnwrapKeyAuthenticated",
]


class CK_FUNCTION_LIST(ctypes.Structure):
    _fields_ = [("version", CK_VERSION)] + [
        (name, ctypes.c_void_p) for name in LEGACY_FUNCTIONS
    ]


class CK_FUNCTION_LIST_3_0(ctypes.Structure):
    _fields_ = [("version", CK_VERSION)] + [
        (name, ctypes.c_void_p) for name in LEGACY_FUNCTIONS + V3_0_FUNCTIONS
    ]


# PKCS #11 3.2 headers do not define a CK_FUNCTION_LIST_3_1 layout.
# A 3.1 request uses the 3.0-shaped table while reporting version 3.1.
CK_FUNCTION_LIST_3_1 = CK_FUNCTION_LIST_3_0


class CK_FUNCTION_LIST_3_2(ctypes.Structure):
    _fields_ = [("version", CK_VERSION)] + [
        (name, ctypes.c_void_p) for name in LEGACY_FUNCTIONS + V3_0_FUNCTIONS + V3_2_FUNCTIONS
    ]


class Pkcs11AbiTests(unittest.TestCase):
    def assert_layout(self, structure, size: int, alignment: int, offsets: dict[str, int]) -> None:
        self.assertEqual(ctypes.sizeof(structure), size, structure.__name__)
        self.assertEqual(ctypes.alignment(structure), alignment, structure.__name__)
        for field, offset in offsets.items():
            self.assertEqual(
                getattr(structure, field).offset,
                offset,
                f"{structure.__name__}.{field}",
            )

    @classmethod
    def setUpClass(cls) -> None:
        cls.lib = load_library()
        cls.lib.C_Initialize.argtypes = [ctypes.c_void_p]
        cls.lib.C_Initialize.restype = CK_RV
        cls.lib.C_Finalize.argtypes = [ctypes.c_void_p]
        cls.lib.C_Finalize.restype = CK_RV
        cls.lib.C_GetFunctionList.argtypes = [ctypes.POINTER(ctypes.POINTER(CK_FUNCTION_LIST))]
        cls.lib.C_GetFunctionList.restype = CK_RV
        cls.lib.C_InitToken.argtypes = [
            CK_ULONG,
            ctypes.POINTER(CK_BYTE),
            CK_ULONG,
            ctypes.POINTER(CK_BYTE),
        ]
        cls.lib.C_InitToken.restype = CK_RV
        cls.lib.C_InitPIN.argtypes = [
            CK_ULONG,
            ctypes.POINTER(CK_BYTE),
            CK_ULONG,
        ]
        cls.lib.C_InitPIN.restype = CK_RV
        cls.lib.C_WaitForSlotEvent.argtypes = [
            CK_FLAGS,
            ctypes.POINTER(CK_ULONG),
            ctypes.c_void_p,
        ]
        cls.lib.C_WaitForSlotEvent.restype = CK_RV
        cls.lib.C_CloseAllSessions.argtypes = [CK_ULONG]
        cls.lib.C_CloseAllSessions.restype = CK_RV
        cls.lib.C_GetFunctionStatus.argtypes = [CK_ULONG]
        cls.lib.C_GetFunctionStatus.restype = CK_RV
        cls.lib.C_GetInfo.argtypes = [ctypes.POINTER(CK_INFO)]
        cls.lib.C_GetInfo.restype = CK_RV
        cls.lib.C_GetMechanismList.argtypes = [
            CK_ULONG,
            ctypes.POINTER(CK_ULONG),
            ctypes.POINTER(CK_ULONG),
        ]
        cls.lib.C_GetMechanismList.restype = CK_RV
        cls.lib.C_GetMechanismInfo.argtypes = [
            CK_ULONG,
            CK_ULONG,
            ctypes.POINTER(CK_MECHANISM_INFO),
        ]
        cls.lib.C_GetMechanismInfo.restype = CK_RV
        cls.lib.C_GenerateRandom.argtypes = [
            CK_ULONG,
            ctypes.POINTER(CK_BYTE),
            CK_ULONG,
        ]
        cls.lib.C_GenerateRandom.restype = CK_RV
        cls.lib.C_GetInterfaceList.argtypes = [
            ctypes.POINTER(CK_INTERFACE),
            ctypes.POINTER(CK_ULONG),
        ]
        cls.lib.C_GetInterfaceList.restype = CK_RV
        cls.lib.C_GetInterface.argtypes = [
            ctypes.c_char_p,
            ctypes.POINTER(CK_VERSION),
            ctypes.POINTER(ctypes.POINTER(CK_INTERFACE)),
            CK_FLAGS,
        ]
        cls.lib.C_GetInterface.restype = CK_RV
        cls.lib.C_MessageEncryptFinal.argtypes = [CK_ULONG]
        cls.lib.C_MessageEncryptFinal.restype = CK_RV
        cls.lib.C_GetSessionValidationFlags.argtypes = [
            CK_ULONG,
            CK_ULONG,
            ctypes.POINTER(CK_FLAGS),
        ]
        cls.lib.C_GetSessionValidationFlags.restype = CK_RV

    def setUp(self) -> None:
        self.lib.C_Finalize(None)

    def tearDown(self) -> None:
        self.lib.C_Finalize(None)

    def assert_function_entries_present(self, function_list, names: list[str]) -> None:
        for name in names:
            self.assertTrue(getattr(function_list, name), name)

    def test_legacy_function_list_entries_are_stubbed(self) -> None:
        function_list = ctypes.POINTER(CK_FUNCTION_LIST)()

        self.assertEqual(self.lib.C_GetFunctionList(ctypes.byref(function_list)), CKR_OK)
        self.assertTrue(function_list)
        self.assertEqual(function_list.contents.version.major, 2)
        self.assertEqual(function_list.contents.version.minor, 40)
        self.assert_function_entries_present(function_list.contents, LEGACY_FUNCTIONS)

    def test_3_2_interface_function_list_entries_are_stubbed(self) -> None:
        version = CK_VERSION(3, 2)
        interface = ctypes.POINTER(CK_INTERFACE)()

        self.assertEqual(
            self.lib.C_GetInterface(b"PKCS 11", ctypes.byref(version), ctypes.byref(interface), 0),
            CKR_OK,
        )
        self.assertTrue(interface)

        function_list = ctypes.cast(
            interface.contents.pFunctionList,
            ctypes.POINTER(CK_FUNCTION_LIST_3_2),
        ).contents
        self.assert_function_entries_present(
            function_list,
            LEGACY_FUNCTIONS + V3_0_FUNCTIONS + V3_2_FUNCTIONS,
        )

    def test_representative_session_stubs_validate_initialization_and_session(self) -> None:
        flags = CK_FLAGS()

        session_stubs = [
            ("C_InitPIN", lambda: self.lib.C_InitPIN(999, None, 0)),
            ("C_GetFunctionStatus", lambda: self.lib.C_GetFunctionStatus(999)),
            ("C_MessageEncryptFinal", lambda: self.lib.C_MessageEncryptFinal(999)),
            (
                "C_GetSessionValidationFlags",
                lambda: self.lib.C_GetSessionValidationFlags(999, 0, ctypes.byref(flags)),
            ),
        ]

        for name, call in session_stubs:
            self.assertEqual(call(), CKR_CRYPTOKI_NOT_INITIALIZED, name)

        self.assertEqual(self.lib.C_Initialize(None), CKR_OK)
        for name, call in session_stubs:
            self.assertEqual(call(), CKR_SESSION_HANDLE_INVALID, name)

    def test_representative_non_session_stubs_report_unsupported(self) -> None:
        slot = CK_ULONG()

        self.assertEqual(self.lib.C_InitToken(0, None, 0, None), CKR_FUNCTION_NOT_SUPPORTED)
        self.assertEqual(
            self.lib.C_WaitForSlotEvent(0, ctypes.byref(slot), None),
            CKR_FUNCTION_NOT_SUPPORTED,
        )

    def test_layout_ck_info(self) -> None:
        self.assert_layout(
            CK_INFO,
            88,
            8,
            {
                "cryptokiVersion": 0,
                "manufacturerID": 2,
                "flags": 40,
                "libraryDescription": 48,
                "libraryVersion": 80,
            },
        )

    def test_layout_ck_slot_info(self) -> None:
        self.assert_layout(
            CK_SLOT_INFO,
            112,
            8,
            {
                "slotDescription": 0,
                "manufacturerID": 64,
                "flags": 96,
                "hardwareVersion": 104,
                "firmwareVersion": 106,
            },
        )

    def test_layout_ck_token_info(self) -> None:
        self.assert_layout(
            CK_TOKEN_INFO,
            208,
            8,
            {
                "label": 0,
                "manufacturerID": 32,
                "model": 64,
                "serialNumber": 80,
                "flags": 96,
                "ulMaxSessionCount": 104,
                "ulSessionCount": 112,
                "ulMaxRwSessionCount": 120,
                "ulRwSessionCount": 128,
                "ulMaxPinLen": 136,
                "ulMinPinLen": 144,
                "ulTotalPublicMemory": 152,
                "ulFreePublicMemory": 160,
                "ulTotalPrivateMemory": 168,
                "ulFreePrivateMemory": 176,
                "hardwareVersion": 184,
                "firmwareVersion": 186,
                "utcTime": 188,
            },
        )

    def test_layout_ck_session_info(self) -> None:
        self.assert_layout(
            CK_SESSION_INFO,
            32,
            8,
            {
                "slotID": 0,
                "state": 8,
                "flags": 16,
                "ulDeviceError": 24,
            },
        )

    def test_layout_ck_attribute(self) -> None:
        self.assert_layout(
            CK_ATTRIBUTE,
            24,
            8,
            {
                "type_": 0,
                "pValue": 8,
                "ulValueLen": 16,
            },
        )

    def test_layout_ck_date(self) -> None:
        self.assert_layout(
            CK_DATE,
            8,
            1,
            {
                "year": 0,
                "month": 4,
                "day": 6,
            },
        )

    def test_layout_ck_mechanism(self) -> None:
        self.assert_layout(
            CK_MECHANISM,
            24,
            8,
            {
                "mechanism": 0,
                "pParameter": 8,
                "ulParameterLen": 16,
            },
        )

    def test_layout_ck_mechanism_info(self) -> None:
        self.assert_layout(
            CK_MECHANISM_INFO,
            24,
            8,
            {
                "ulMinKeySize": 0,
                "ulMaxKeySize": 8,
                "flags": 16,
            },
        )

    def test_layout_ck_ecdh1_derive_params(self) -> None:
        self.assert_layout(
            CK_ECDH1_DERIVE_PARAMS,
            40,
            8,
            {
                "kdf": 0,
                "ulSharedDataLen": 8,
                "pSharedData": 16,
                "ulPublicDataLen": 24,
                "pPublicData": 32,
            },
        )

    def test_layout_ck_rsa_pkcs_oaep_params(self) -> None:
        self.assert_layout(
            CK_RSA_PKCS_OAEP_PARAMS,
            40,
            8,
            {
                "hashAlg": 0,
                "mgf": 8,
                "source": 16,
                "pSourceData": 24,
                "ulSourceDataLen": 32,
            },
        )

    def test_layout_ck_rsa_pkcs_pss_params(self) -> None:
        self.assert_layout(
            CK_RSA_PKCS_PSS_PARAMS,
            24,
            8,
            {
                "hashAlg": 0,
                "mgf": 8,
                "sLen": 16,
            },
        )

    def test_layout_ck_version(self) -> None:
        self.assert_layout(
            CK_VERSION,
            2,
            1,
            {
                "major": 0,
                "minor": 1,
            },
        )

    def test_layout_ck_c_initialize_args(self) -> None:
        self.assert_layout(
            CK_C_INITIALIZE_ARGS,
            48,
            8,
            {
                "CreateMutex": 0,
                "DestroyMutex": 8,
                "LockMutex": 16,
                "UnlockMutex": 24,
                "flags": 32,
                "pReserved": 40,
            },
        )

    def test_layout_ck_function_list(self) -> None:
        self.assert_layout(CK_FUNCTION_LIST, 552, 8, {"version": 0})
        for index, name in enumerate(LEGACY_FUNCTIONS):
            self.assertEqual(
                getattr(CK_FUNCTION_LIST, name).offset,
                8 + index * ctypes.sizeof(ctypes.c_void_p),
                f"CK_FUNCTION_LIST.{name}",
            )

    def test_get_info_reports_cryptoki_3_2(self) -> None:
        self.assertEqual(self.lib.C_Initialize(None), CKR_OK)
        info = CK_INFO()

        self.assertEqual(self.lib.C_GetInfo(ctypes.byref(info)), CKR_OK)

        self.assertEqual(info.cryptokiVersion.major, 3)
        self.assertEqual(info.cryptokiVersion.minor, 2)

    def test_initialize_and_finalize_reject_reserved_args(self) -> None:
        init_args = CK_C_INITIALIZE_ARGS()
        init_args.pReserved = ctypes.c_void_p(1)

        self.assertEqual(self.lib.C_Initialize(ctypes.byref(init_args)), CKR_ARGUMENTS_BAD)
        self.assertEqual(self.lib.C_Finalize(ctypes.c_void_p(1)), CKR_ARGUMENTS_BAD)

    def test_slot_and_mechanism_calls_validate_slot_ids(self) -> None:
        self.assertEqual(self.lib.C_Initialize(None), CKR_OK)
        count = CK_ULONG()
        info = CK_MECHANISM_INFO()

        self.assertEqual(self.lib.C_CloseAllSessions(999), CKR_SLOT_ID_INVALID)
        self.assertEqual(
            self.lib.C_GetMechanismList(999, None, ctypes.byref(count)),
            CKR_SLOT_ID_INVALID,
        )
        self.assertEqual(
            self.lib.C_GetMechanismInfo(999, CKM_RSA_PKCS, ctypes.byref(info)),
            CKR_SLOT_ID_INVALID,
        )

    def test_generate_random_validates_initialization_and_session(self) -> None:
        random_data = (CK_BYTE * 16)()

        self.assertEqual(
            self.lib.C_GenerateRandom(1, random_data, len(random_data)),
            CKR_CRYPTOKI_NOT_INITIALIZED,
        )
        self.assertEqual(self.lib.C_Initialize(None), CKR_OK)
        self.assertEqual(
            self.lib.C_GenerateRandom(999, random_data, len(random_data)),
            CKR_SESSION_HANDLE_INVALID,
        )

    def test_interface_list_reports_one_pkcs11_interface(self) -> None:
        count = CK_ULONG()

        self.assertEqual(self.lib.C_GetInterfaceList(None, ctypes.byref(count)), CKR_OK)
        self.assertEqual(count.value, 1)

        interface = CK_INTERFACE()
        self.assertEqual(
            self.lib.C_GetInterfaceList(ctypes.byref(interface), ctypes.byref(count)),
            CKR_OK,
        )

        self.assertEqual(count.value, 1)
        self.assertEqual(ctypes.string_at(interface.pInterfaceName), b"PKCS 11")
        self.assertTrue(interface.pFunctionList)
        self.assertEqual(interface.flags, 0)

    def test_interface_list_checks_buffer_size(self) -> None:
        count = CK_ULONG(0)
        interface = CK_INTERFACE()

        self.assertEqual(
            self.lib.C_GetInterfaceList(ctypes.byref(interface), ctypes.byref(count)),
            CKR_BUFFER_TOO_SMALL,
        )
        self.assertEqual(count.value, 1)

    def test_get_interface_returns_3_2_function_table(self) -> None:
        version = CK_VERSION(3, 2)
        interface = ctypes.POINTER(CK_INTERFACE)()

        self.assertEqual(
            self.lib.C_GetInterface(b"PKCS 11", ctypes.byref(version), ctypes.byref(interface), 0),
            CKR_OK,
        )
        self.assertTrue(interface)

        function_list = ctypes.cast(
            interface.contents.pFunctionList,
            ctypes.POINTER(CK_FUNCTION_LIST_3_2),
        ).contents
        self.assertEqual(function_list.version.major, 3)
        self.assertEqual(function_list.version.minor, 2)

        for name in ["C_GetInterface", "C_EncapsulateKey", "C_UnwrapKeyAuthenticated"]:
            self.assertTrue(getattr(function_list, name), name)

    def test_get_interface_returns_3_0_shaped_table_for_3_1_request(self) -> None:
        version = CK_VERSION(3, 1)
        interface = ctypes.POINTER(CK_INTERFACE)()

        self.assertEqual(
            self.lib.C_GetInterface(b"PKCS 11", ctypes.byref(version), ctypes.byref(interface), 0),
            CKR_OK,
        )
        self.assertTrue(interface)

        function_list = ctypes.cast(
            interface.contents.pFunctionList,
            ctypes.POINTER(CK_FUNCTION_LIST_3_1),
        ).contents
        self.assertEqual(function_list.version.major, 3)
        self.assertEqual(function_list.version.minor, 1)

        for name in ["C_GetInterface", "C_MessageEncryptInit", "C_MessageVerifyFinal"]:
            self.assertTrue(getattr(function_list, name), name)

    def test_get_interface_returns_3_0_function_table_for_3_0_request(self) -> None:
        version = CK_VERSION(3, 0)
        interface = ctypes.POINTER(CK_INTERFACE)()

        self.assertEqual(
            self.lib.C_GetInterface(b"PKCS 11", ctypes.byref(version), ctypes.byref(interface), 0),
            CKR_OK,
        )
        self.assertTrue(interface)

        function_list = ctypes.cast(
            interface.contents.pFunctionList,
            ctypes.POINTER(CK_FUNCTION_LIST_3_0),
        ).contents
        self.assertEqual(function_list.version.major, 3)
        self.assertEqual(function_list.version.minor, 0)

        for name in ["C_GetInterface", "C_MessageEncryptInit", "C_MessageVerifyFinal"]:
            self.assertTrue(getattr(function_list, name), name)

    def test_get_interface_returns_2_40_function_table_for_2_40_request(self) -> None:
        version = CK_VERSION(2, 40)
        interface = ctypes.POINTER(CK_INTERFACE)()

        self.assertEqual(
            self.lib.C_GetInterface(b"PKCS 11", ctypes.byref(version), ctypes.byref(interface), 0),
            CKR_OK,
        )
        self.assertTrue(interface)

        function_list = ctypes.cast(
            interface.contents.pFunctionList,
            ctypes.POINTER(CK_FUNCTION_LIST),
        ).contents
        self.assertEqual(function_list.version.major, 2)
        self.assertEqual(function_list.version.minor, 40)

        for name in ["C_GetFunctionList", "C_Initialize", "C_Finalize"]:
            self.assertTrue(getattr(function_list, name), name)

    def test_get_interface_rejects_wrong_version(self) -> None:
        for major, minor in [(2, 39), (3, 3), (3, 4)]:
            version = CK_VERSION(major, minor)
            interface = ctypes.POINTER(CK_INTERFACE)()

            self.assertEqual(
                self.lib.C_GetInterface(
                    b"PKCS 11",
                    ctypes.byref(version),
                    ctypes.byref(interface),
                    0,
                ),
                CKR_ARGUMENTS_BAD,
                f"{major}.{minor}",
            )

    def test_get_interface_rejects_wrong_name(self) -> None:
        version = CK_VERSION(3, 2)
        interface = ctypes.POINTER(CK_INTERFACE)()

        self.assertEqual(
            self.lib.C_GetInterface(b"NOT PKCS", ctypes.byref(version), ctypes.byref(interface), 0),
            CKR_ARGUMENTS_BAD,
        )


if __name__ == "__main__":
    unittest.main()
