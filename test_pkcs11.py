#!/usr/bin/env python3
"""ctypes smoke tests for the pkcs11rs shared library."""

from __future__ import annotations

import ctypes
import pathlib
import platform
import subprocess
import unittest


ROOT = pathlib.Path(__file__).resolve().parent
ABI_TARGET = ROOT / "target" / "abi-tests"
CKR_OK = 0
CKR_SLOT_ID_INVALID = 3
CKR_CANT_LOCK = 0xA
CKR_BUFFER_TOO_SMALL = 0x150
CKR_ARGUMENTS_BAD = 7
CKR_ATTRIBUTE_READ_ONLY = 0x10
CKR_ATTRIBUTE_SENSITIVE = 0x11
CKR_DATA_LEN_RANGE = 0x21
CKR_ENCRYPTED_DATA_INVALID = 0x40
CKR_FUNCTION_NOT_SUPPORTED = 0x54
CKR_KEY_SIZE_RANGE = 0x62
CKR_KEY_TYPE_INCONSISTENT = 0x63
CKR_MECHANISM_INVALID = 0x70
CKR_OBJECT_HANDLE_INVALID = 0x82
CKR_OPERATION_NOT_INITIALIZED = 0x91
CKR_PIN_INCORRECT = 0xA0
CKR_SESSION_HANDLE_INVALID = 0xB3
CKR_SESSION_PARALLEL_NOT_SUPPORTED = 0xB4
CKR_SESSION_READ_ONLY = 0xB5
CKR_SIGNATURE_INVALID = 0xC0
CKR_SIGNATURE_LEN_RANGE = 0xC1
CKR_TEMPLATE_INCOMPLETE = 0xD0
CKR_TEMPLATE_INCONSISTENT = 0xD1
CKR_USER_ALREADY_LOGGED_IN = 0x100
CKR_USER_NOT_LOGGED_IN = 0x101
CKR_USER_TYPE_INVALID = 0x103
CKR_CRYPTOKI_NOT_INITIALIZED = 0x190
CKR_SESSION_ASYNC_NOT_SUPPORTED = 0x205
CKF_RW_SESSION = 0x00000002
CKF_SERIAL_SESSION = 0x00000004
CKF_ASYNC_SESSION = 0x00000008
CKF_OS_LOCKING_OK = 0x00000002
CKF_INTERFACE_FORK_SAFE = 0x00000001
CKF_GENERATE = 0x00008000
CKM_RSA_PKCS_KEY_PAIR_GEN = 0x00000000
CKM_RSA_PKCS = 0x00000001
CKM_GENERIC_SECRET_KEY_GEN = 0x00000350
CKM_EC_KEY_PAIR_GEN = 0x00001040
CKM_ECDSA = 0x00001041
CKM_AES_ECB = 0x00001081
CKM_AES_CBC = 0x00001082
CKM_AES_GCM = 0x00001087
CKO_SECRET_KEY = 0x00000004
CKO_PRIVATE_KEY = 0x00000003
CKO_PUBLIC_KEY = 0x00000002
CKO_DATA = 0x00000000
CKO_CERTIFICATE = 0x00000001
CKC_X_509 = 0x00000000
CKK_GENERIC_SECRET = 0x00000010
CKK_RSA = 0x00000000
CKK_YUBICO_AES128_CCM_WRAP = 0xD955421D
CKA_CLASS = 0x00000000
CKA_TOKEN = 0x00000001
CKA_PRIVATE = 0x00000002
CKA_LABEL = 0x00000003
CKA_UNIQUE_ID = 0x00000004
CKA_APPLICATION = 0x00000010
CKA_VALUE = 0x00000011
CKA_OBJECT_ID = 0x00000012
CKA_CERTIFICATE_TYPE = 0x00000080
CKA_ISSUER = 0x00000081
CKA_SERIAL_NUMBER = 0x00000082
CKA_KEY_TYPE = 0x00000100
CKA_SUBJECT = 0x00000101
CKA_ID = 0x00000102
CKA_SENSITIVE = 0x00000103
CKA_ENCRYPT = 0x00000104
CKA_DECRYPT = 0x00000105
CKA_WRAP = 0x00000106
CKA_UNWRAP = 0x00000107
CKA_SIGN = 0x00000108
CKA_VERIFY = 0x0000010A
CKA_DERIVE = 0x0000010C
CKA_MODULUS = 0x00000120
CKA_MODULUS_BITS = 0x00000121
CKA_VALUE_LEN = 0x00000161
CKA_EXTRACTABLE = 0x00000162
CKA_LOCAL = 0x00000163
CKA_NEVER_EXTRACTABLE = 0x00000164
CKA_ALWAYS_SENSITIVE = 0x00000165
CKA_KEY_GEN_MECHANISM = 0x00000166
CKA_MODIFIABLE = 0x00000170
CKA_COPYABLE = 0x00000171
CKA_DESTROYABLE = 0x00000172
CKU_SO = 0
CKU_USER = 1
CKS_RO_PUBLIC_SESSION = 0
CKS_RO_USER_FUNCTIONS = 1
CKS_RW_PUBLIC_SESSION = 2
CKS_RW_USER_FUNCTIONS = 3
ABI_TEST_SLOT_ID = 77
ABI_TEST_PIV_SLOT_ID = 78
ABI_TEST_SCP03_SLOT_ID = 79
ABI_TEST_YUBIHSM_SLOT_ID = 80
ABI_TEST_SCP11_SLOT_ID = 81
CK_UNAVAILABLE_INFORMATION = (1 << (ctypes.sizeof(ctypes.c_ulong) * 8)) - 1


def library_path() -> pathlib.Path:
    system = platform.system()
    if system == "Darwin":
        name = "libpkcs11rs.dylib"
    elif system == "Windows":
        name = "pkcs11rs.dll"
    else:
        name = "libpkcs11rs.so"
    return ABI_TARGET / "debug" / name


def load_library() -> ctypes.CDLL:
    path = library_path()
    subprocess.run(
        [
            "cargo",
            "build",
            "--features",
            "abi-tests",
            "--target-dir",
            str(ABI_TARGET),
        ],
        cwd=ROOT,
        check=True,
    )
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


class CK_GCM_PARAMS(ctypes.Structure):
    _fields_ = [
        ("pIv", ctypes.POINTER(CK_BYTE)),
        ("ulIvLen", CK_ULONG),
        ("ulIvBits", CK_ULONG),
        ("pAAD", ctypes.POINTER(CK_BYTE)),
        ("ulAADLen", CK_ULONG),
        ("ulTagBits", CK_ULONG),
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
        cls.lib.C_GetSlotList.argtypes = [
            CK_BYTE,
            ctypes.POINTER(CK_ULONG),
            ctypes.POINTER(CK_ULONG),
        ]
        cls.lib.C_GetSlotList.restype = CK_RV
        cls.lib.C_OpenSession.argtypes = [
            CK_ULONG,
            CK_FLAGS,
            CK_VOID_PTR,
            CK_VOID_PTR,
            ctypes.POINTER(CK_ULONG),
        ]
        cls.lib.C_OpenSession.restype = CK_RV
        cls.lib.C_CloseSession.argtypes = [CK_ULONG]
        cls.lib.C_CloseSession.restype = CK_RV
        cls.lib.C_GetSessionInfo.argtypes = [
            CK_ULONG,
            ctypes.POINTER(CK_SESSION_INFO),
        ]
        cls.lib.C_GetSessionInfo.restype = CK_RV
        cls.lib.C_GetTokenInfo.argtypes = [
            CK_ULONG,
            ctypes.POINTER(CK_TOKEN_INFO),
        ]
        cls.lib.C_GetTokenInfo.restype = CK_RV
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
        cls.lib.C_GetMechanismInfo.argtypes = [
            CK_ULONG,
            CK_ULONG,
            ctypes.POINTER(CK_MECHANISM_INFO),
        ]
        cls.lib.C_GetMechanismInfo.restype = CK_RV
        cls.lib.C_CreateObject.argtypes = [
            CK_ULONG,
            ctypes.POINTER(CK_ATTRIBUTE),
            CK_ULONG,
            ctypes.POINTER(CK_ULONG),
        ]
        cls.lib.C_CreateObject.restype = CK_RV
        cls.lib.C_CopyObject.argtypes = [
            CK_ULONG,
            CK_ULONG,
            ctypes.POINTER(CK_ATTRIBUTE),
            CK_ULONG,
            ctypes.POINTER(CK_ULONG),
        ]
        cls.lib.C_CopyObject.restype = CK_RV
        cls.lib.C_DestroyObject.argtypes = [CK_ULONG, CK_ULONG]
        cls.lib.C_DestroyObject.restype = CK_RV
        cls.lib.C_GetObjectSize.argtypes = [
            CK_ULONG,
            CK_ULONG,
            ctypes.POINTER(CK_ULONG),
        ]
        cls.lib.C_GetObjectSize.restype = CK_RV
        cls.lib.C_GetAttributeValue.argtypes = [
            CK_ULONG,
            CK_ULONG,
            ctypes.POINTER(CK_ATTRIBUTE),
            CK_ULONG,
        ]
        cls.lib.C_GetAttributeValue.restype = CK_RV
        cls.lib.C_SetAttributeValue.argtypes = [
            CK_ULONG,
            CK_ULONG,
            ctypes.POINTER(CK_ATTRIBUTE),
            CK_ULONG,
        ]
        cls.lib.C_SetAttributeValue.restype = CK_RV
        cls.lib.C_FindObjectsInit.argtypes = [
            CK_ULONG,
            ctypes.POINTER(CK_ATTRIBUTE),
            CK_ULONG,
        ]
        cls.lib.C_FindObjectsInit.restype = CK_RV
        cls.lib.C_FindObjects.argtypes = [
            CK_ULONG,
            ctypes.POINTER(CK_ULONG),
            CK_ULONG,
            ctypes.POINTER(CK_ULONG),
        ]
        cls.lib.C_FindObjects.restype = CK_RV
        cls.lib.C_FindObjectsFinal.argtypes = [CK_ULONG]
        cls.lib.C_FindObjectsFinal.restype = CK_RV
        cls.lib.C_EncryptInit.argtypes = [
            CK_ULONG,
            ctypes.POINTER(CK_MECHANISM),
            CK_ULONG,
        ]
        cls.lib.C_EncryptInit.restype = CK_RV
        cls.lib.C_Encrypt.argtypes = [
            CK_ULONG,
            ctypes.POINTER(CK_BYTE),
            CK_ULONG,
            ctypes.POINTER(CK_BYTE),
            ctypes.POINTER(CK_ULONG),
        ]
        cls.lib.C_Encrypt.restype = CK_RV
        cls.lib.C_DecryptInit.argtypes = [
            CK_ULONG,
            ctypes.POINTER(CK_MECHANISM),
            CK_ULONG,
        ]
        cls.lib.C_DecryptInit.restype = CK_RV
        cls.lib.C_Decrypt.argtypes = [
            CK_ULONG,
            ctypes.POINTER(CK_BYTE),
            CK_ULONG,
            ctypes.POINTER(CK_BYTE),
            ctypes.POINTER(CK_ULONG),
        ]
        cls.lib.C_Decrypt.restype = CK_RV
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
        cls.lib.C_SignUpdate.argtypes = [
            CK_ULONG,
            ctypes.POINTER(CK_BYTE),
            CK_ULONG,
        ]
        cls.lib.C_SignUpdate.restype = CK_RV
        cls.lib.C_SignFinal.argtypes = [
            CK_ULONG,
            ctypes.POINTER(CK_BYTE),
            ctypes.POINTER(CK_ULONG),
        ]
        cls.lib.C_SignFinal.restype = CK_RV
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
        cls.lib.C_VerifyUpdate.argtypes = [
            CK_ULONG,
            ctypes.POINTER(CK_BYTE),
            CK_ULONG,
        ]
        cls.lib.C_VerifyUpdate.restype = CK_RV
        cls.lib.C_VerifyFinal.argtypes = [
            CK_ULONG,
            ctypes.POINTER(CK_BYTE),
            CK_ULONG,
        ]
        cls.lib.C_VerifyFinal.restype = CK_RV
        cls.lib.C_GenerateKey.argtypes = [
            CK_ULONG,
            ctypes.POINTER(CK_MECHANISM),
            ctypes.POINTER(CK_ATTRIBUTE),
            CK_ULONG,
            ctypes.POINTER(CK_ULONG),
        ]
        cls.lib.C_GenerateKey.restype = CK_RV
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

    def initialize_and_open_session(self) -> int:
        self.assertEqual(self.lib.C_Initialize(None), CKR_OK)
        session = CK_ULONG()
        self.assertEqual(
            self.lib.C_OpenSession(
                ABI_TEST_SLOT_ID,
                CKF_SERIAL_SESSION,
                None,
                None,
                ctypes.byref(session),
            ),
            CKR_OK,
        )
        return session.value

    def login_session(self, session: int) -> None:
        pin = (CK_BYTE * 4)(*b"1234")
        self.assertEqual(
            self.lib.C_Login(session, CKU_USER, pin, len(pin)),
            CKR_OK,
        )

    def open_slot_session(self, slot_id: int) -> int:
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

    def login_with_pin(self, session: int, value: bytes) -> None:
        pin = (CK_BYTE * len(value))(*value)
        self.assertEqual(
            self.lib.C_Login(session, CKU_USER, pin, len(pin)),
            CKR_OK,
        )

    def test_abi_hardware_fixtures_are_present_without_real_hardware(self) -> None:
        self.assertEqual(self.lib.C_Initialize(None), CKR_OK)
        count = CK_ULONG()
        self.assertEqual(self.lib.C_GetSlotList(1, None, ctypes.byref(count)), CKR_OK)
        slots = (CK_ULONG * count.value)()
        self.assertEqual(
            self.lib.C_GetSlotList(1, slots, ctypes.byref(count)),
            CKR_OK,
        )
        self.assertEqual(list(slots), [
            ABI_TEST_SLOT_ID,
            ABI_TEST_PIV_SLOT_ID,
            ABI_TEST_SCP03_SLOT_ID,
            ABI_TEST_YUBIHSM_SLOT_ID,
            ABI_TEST_SCP11_SLOT_ID,
        ])

    def test_abi_piv_fixture_exercises_sign_dispatch(self) -> None:
        self.assertEqual(self.lib.C_Initialize(None), CKR_OK)
        session = self.open_slot_session(ABI_TEST_PIV_SLOT_ID)
        self.login_with_pin(session, b"123456")

        object_class = CK_ULONG(CKO_PRIVATE_KEY)
        template = (CK_ATTRIBUTE * 1)(
            CK_ATTRIBUTE(
                CKA_CLASS,
                ctypes.cast(ctypes.byref(object_class), CK_VOID_PTR),
                ctypes.sizeof(object_class),
            )
        )
        self.assertEqual(
            self.lib.C_FindObjectsInit(session, template, len(template)), CKR_OK
        )
        handle = CK_ULONG()
        found = CK_ULONG()
        self.assertEqual(
            self.lib.C_FindObjects(session, ctypes.byref(handle), 1, ctypes.byref(found)),
            CKR_OK,
        )
        self.assertEqual((found.value, handle.value), (1, 4))
        self.assertEqual(self.lib.C_FindObjectsFinal(session), CKR_OK)

        mechanism = CK_MECHANISM(CKM_RSA_PKCS, None, 0)
        data = (CK_BYTE * 4)(1, 2, 3, 4)
        signature_len = CK_ULONG()
        self.assertEqual(
            self.lib.C_SignInit(session, ctypes.byref(mechanism), handle.value), CKR_OK
        )
        self.assertEqual(
            self.lib.C_Sign(
                session, data, len(data), None, ctypes.byref(signature_len)
            ),
            CKR_OK,
        )
        self.assertEqual(signature_len.value, 256)

    def test_abi_scp03_fixture_exercises_secure_session_dispatch(self) -> None:
        self.assertEqual(self.lib.C_Initialize(None), CKR_OK)
        session = self.open_slot_session(ABI_TEST_SCP03_SLOT_ID)
        self.login_session(session)
        random_data = (CK_BYTE * 16)()
        self.assertEqual(
            self.lib.C_GenerateRandom(session, random_data, len(random_data)), CKR_OK
        )
        self.assertEqual(bytes(random_data), bytes(16))

    def test_abi_scp11_fixture_exercises_secure_session_dispatch(self) -> None:
        self.assertEqual(self.lib.C_Initialize(None), CKR_OK)
        session = self.open_slot_session(ABI_TEST_SCP11_SLOT_ID)
        self.login_session(session)
        random_data = (CK_BYTE * 16)()
        self.assertEqual(
            self.lib.C_GenerateRandom(session, random_data, len(random_data)), CKR_OK
        )
        self.assertEqual(bytes(random_data), bytes(16))

    def test_abi_yubihsm_fixture_exercises_remote_sign_dispatch(self) -> None:
        self.assertEqual(self.lib.C_Initialize(None), CKR_OK)
        session = self.open_slot_session(ABI_TEST_YUBIHSM_SLOT_ID)
        self.login_session(session)

        object_class = CK_ULONG(CKO_PRIVATE_KEY)
        template = (CK_ATTRIBUTE * 1)(
            CK_ATTRIBUTE(
                CKA_CLASS,
                ctypes.cast(ctypes.byref(object_class), CK_VOID_PTR),
                ctypes.sizeof(object_class),
            )
        )
        self.assertEqual(
            self.lib.C_FindObjectsInit(session, template, len(template)), CKR_OK
        )
        handle = CK_ULONG()
        found = CK_ULONG()
        self.assertEqual(
            self.lib.C_FindObjects(session, ctypes.byref(handle), 1, ctypes.byref(found)),
            CKR_OK,
        )
        self.assertEqual(found.value, 1)
        self.assertEqual(self.lib.C_FindObjectsFinal(session), CKR_OK)

        mechanism = CK_MECHANISM(CKM_RSA_PKCS, None, 0)
        data = (CK_BYTE * 4)(1, 2, 3, 4)
        signature_len = CK_ULONG()
        self.assertEqual(
            self.lib.C_SignInit(session, ctypes.byref(mechanism), handle.value), CKR_OK
        )
        self.assertEqual(
            self.lib.C_Sign(
                session, data, len(data), None, ctypes.byref(signature_len)
            ),
            CKR_OK,
        )
        self.assertEqual(signature_len.value, 256)

    def test_abi_yubihsm_fixture_exercises_aes_gcm(self) -> None:
        self.assertEqual(self.lib.C_Initialize(None), CKR_OK)
        session = self.open_slot_session(ABI_TEST_YUBIHSM_SLOT_ID)
        self.login_session(session)

        mechanism_count = CK_ULONG()
        self.assertEqual(
            self.lib.C_GetMechanismList(
                ABI_TEST_YUBIHSM_SLOT_ID, None, ctypes.byref(mechanism_count)
            ),
            CKR_OK,
        )
        mechanisms = (CK_ULONG * mechanism_count.value)()
        self.assertEqual(
            self.lib.C_GetMechanismList(
                ABI_TEST_YUBIHSM_SLOT_ID,
                mechanisms,
                ctypes.byref(mechanism_count),
            ),
            CKR_OK,
        )
        self.assertIn(CKM_AES_GCM, mechanisms)

        object_class = CK_ULONG(CKO_SECRET_KEY)
        template = (CK_ATTRIBUTE * 1)(
            CK_ATTRIBUTE(
                CKA_CLASS,
                ctypes.cast(ctypes.byref(object_class), CK_VOID_PTR),
                ctypes.sizeof(object_class),
            )
        )
        self.assertEqual(
            self.lib.C_FindObjectsInit(session, template, len(template)), CKR_OK
        )
        handle = CK_ULONG()
        found = CK_ULONG()
        self.assertEqual(
            self.lib.C_FindObjects(session, ctypes.byref(handle), 1, ctypes.byref(found)),
            CKR_OK,
        )
        self.assertEqual(found.value, 1)
        self.assertEqual(self.lib.C_FindObjectsFinal(session), CKR_OK)

        iv = (CK_BYTE * 12)()
        parameters = CK_GCM_PARAMS(iv, len(iv), len(iv) * 8, None, 0, 128)
        mechanism = CK_MECHANISM(
            CKM_AES_GCM,
            ctypes.cast(ctypes.byref(parameters), CK_VOID_PTR),
            ctypes.sizeof(parameters),
        )
        plaintext = (CK_BYTE * 16)()
        encrypted = (CK_BYTE * 32)()
        encrypted_len = CK_ULONG(len(encrypted))
        self.assertEqual(
            self.lib.C_EncryptInit(session, ctypes.byref(mechanism), handle.value), CKR_OK
        )
        self.assertEqual(
            self.lib.C_Encrypt(
                session,
                plaintext,
                len(plaintext),
                encrypted,
                ctypes.byref(encrypted_len),
            ),
            CKR_OK,
        )
        self.assertEqual(encrypted_len.value, 32)
        self.assertEqual(
            bytes(encrypted),
            bytes.fromhex(
                "0388dace60b6a392f328c2b971b2fe78"
                "ab6e47d42cec13bdf53a67b21257bddf"
            ),
        )

        decrypted = (CK_BYTE * 16)()
        decrypted_len = CK_ULONG(len(decrypted))
        self.assertEqual(
            self.lib.C_DecryptInit(session, ctypes.byref(mechanism), handle.value), CKR_OK
        )
        self.assertEqual(
            self.lib.C_Decrypt(
                session,
                encrypted,
                encrypted_len.value,
                decrypted,
                ctypes.byref(decrypted_len),
            ),
            CKR_OK,
        )
        self.assertEqual((decrypted_len.value, bytes(decrypted)), (16, bytes(16)))

        encrypted[31] ^= 1
        self.assertEqual(
            self.lib.C_DecryptInit(session, ctypes.byref(mechanism), handle.value), CKR_OK
        )
        self.assertEqual(
            self.lib.C_Decrypt(
                session,
                encrypted,
                encrypted_len.value,
                decrypted,
                ctypes.byref(decrypted_len),
            ),
            CKR_ENCRYPTED_DATA_INVALID,
        )

    def test_abi_yubihsm_aes_ecb_and_cbc_match_nist_vectors(self) -> None:
        self.assertEqual(self.lib.C_Initialize(None), CKR_OK)
        session = self.open_slot_session(ABI_TEST_YUBIHSM_SLOT_ID)
        self.login_session(session)

        key_id = (CK_BYTE * 2)(0, 3)
        template = (CK_ATTRIBUTE * 1)(
            CK_ATTRIBUTE(
                CKA_ID,
                ctypes.cast(key_id, CK_VOID_PTR),
                len(key_id),
            )
        )
        self.assertEqual(
            self.lib.C_FindObjectsInit(session, template, len(template)), CKR_OK
        )
        handle = CK_ULONG()
        found = CK_ULONG()
        self.assertEqual(
            self.lib.C_FindObjects(session, ctypes.byref(handle), 1, ctypes.byref(found)),
            CKR_OK,
        )
        self.assertEqual(found.value, 1)
        self.assertEqual(self.lib.C_FindObjectsFinal(session), CKR_OK)

        plaintext_bytes = bytes.fromhex(
            "6bc1bee22e409f96e93d7e117393172a"
            "ae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411e5fbc1191a0a52ef"
            "f69f2445df4f9b17ad2b417be66c3710"
        )

        def assert_vector(mechanism: CK_MECHANISM, expected: bytes) -> None:
            plaintext = (CK_BYTE * len(plaintext_bytes)).from_buffer_copy(
                plaintext_bytes
            )
            encrypted = (CK_BYTE * len(expected))()
            encrypted_len = CK_ULONG(len(encrypted))
            self.assertEqual(
                self.lib.C_EncryptInit(
                    session, ctypes.byref(mechanism), handle.value
                ),
                CKR_OK,
            )
            self.assertEqual(
                self.lib.C_Encrypt(
                    session,
                    plaintext,
                    len(plaintext),
                    encrypted,
                    ctypes.byref(encrypted_len),
                ),
                CKR_OK,
            )
            self.assertEqual(bytes(encrypted[: encrypted_len.value]), expected)

            decrypted = (CK_BYTE * len(plaintext_bytes))()
            decrypted_len = CK_ULONG(len(decrypted))
            self.assertEqual(
                self.lib.C_DecryptInit(
                    session, ctypes.byref(mechanism), handle.value
                ),
                CKR_OK,
            )
            self.assertEqual(
                self.lib.C_Decrypt(
                    session,
                    encrypted,
                    encrypted_len.value,
                    decrypted,
                    ctypes.byref(decrypted_len),
                ),
                CKR_OK,
            )
            self.assertEqual(
                bytes(decrypted[: decrypted_len.value]), plaintext_bytes
            )

        # NIST SP 800-38A, Appendices F.1.1/F.1.2.
        assert_vector(
            CK_MECHANISM(CKM_AES_ECB, None, 0),
            bytes.fromhex(
                "3ad77bb40d7a3660a89ecaf32466ef97"
                "f5d3d58503b9699de785895a96fdbaaf"
                "43b1cd7f598ece23881b00e3ed030688"
                "7b0c785e27e8ad3f8223207104725dd4"
            ),
        )

        # NIST SP 800-38A, Appendices F.2.1/F.2.2.
        iv = (CK_BYTE * 16).from_buffer_copy(
            bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        )
        assert_vector(
            CK_MECHANISM(CKM_AES_CBC, ctypes.cast(iv, CK_VOID_PTR), len(iv)),
            bytes.fromhex(
                "7649abac8119b246cee98e9b12e9197d"
                "5086cb9b507219ee95db113a917678b2"
                "73bed6b8e3c1743b7116e69e22229516"
                "3ff1caa1681fac09120eca307586e1a7"
            ),
        )

    def test_abi_yubihsm_authentication_keys_are_generic_secrets(self) -> None:
        self.assertEqual(self.lib.C_Initialize(None), CKR_OK)
        session = self.open_slot_session(ABI_TEST_YUBIHSM_SLOT_ID)
        self.login_session(session)

        for object_id, expected_length in ((4, 32), (7, 64)):
            key_id = (CK_BYTE * 2)(0, object_id)
            template = (CK_ATTRIBUTE * 1)(
                CK_ATTRIBUTE(CKA_ID, ctypes.cast(key_id, CK_VOID_PTR), len(key_id))
            )
            self.assertEqual(
                self.lib.C_FindObjectsInit(session, template, len(template)), CKR_OK
            )
            handle = CK_ULONG()
            found = CK_ULONG()
            self.assertEqual(
                self.lib.C_FindObjects(
                    session, ctypes.byref(handle), 1, ctypes.byref(found)
                ),
                CKR_OK,
            )
            self.assertEqual(found.value, 1)
            self.assertEqual(self.lib.C_FindObjectsFinal(session), CKR_OK)

            object_class = CK_ULONG()
            key_type = CK_ULONG()
            value_len = CK_ULONG()
            generation_mechanism = CK_ULONG()
            encrypt = CK_BYTE()
            decrypt = CK_BYTE()
            sign = CK_BYTE()
            verify = CK_BYTE()
            derive = CK_BYTE()

            def attribute(
                attribute_type: int, value: ctypes._SimpleCData
            ) -> CK_ATTRIBUTE:
                return CK_ATTRIBUTE(
                    attribute_type,
                    ctypes.cast(ctypes.byref(value), CK_VOID_PTR),
                    ctypes.sizeof(value),
                )

            attributes = (CK_ATTRIBUTE * 9)(
                attribute(CKA_CLASS, object_class),
                attribute(CKA_KEY_TYPE, key_type),
                attribute(CKA_VALUE_LEN, value_len),
                attribute(CKA_KEY_GEN_MECHANISM, generation_mechanism),
                attribute(CKA_ENCRYPT, encrypt),
                attribute(CKA_DECRYPT, decrypt),
                attribute(CKA_SIGN, sign),
                attribute(CKA_VERIFY, verify),
                attribute(CKA_DERIVE, derive),
            )
            self.assertEqual(
                self.lib.C_GetAttributeValue(
                    session, handle.value, attributes, len(attributes)
                ),
                CKR_OK,
            )
            self.assertEqual(object_class.value, CKO_SECRET_KEY)
            self.assertEqual(key_type.value, CKK_GENERIC_SECRET)
            self.assertEqual(value_len.value, expected_length)
            self.assertEqual(
                generation_mechanism.value, CK_UNAVAILABLE_INFORMATION
            )
            self.assertEqual(
                (encrypt.value, decrypt.value, sign.value, verify.value, derive.value),
                (0, 0, 0, 0, 0),
            )

    def test_abi_yubihsm_wrap_key_object_types_match_reference(self) -> None:
        self.assertEqual(self.lib.C_Initialize(None), CKR_OK)
        session = self.open_slot_session(ABI_TEST_YUBIHSM_SLOT_ID)
        self.login_session(session)

        def find_one(object_id: int, object_class: int) -> int:
            encoded_id = (CK_BYTE * 2)(*object_id.to_bytes(2, "big"))
            encoded_class = CK_ULONG(object_class)
            template = (CK_ATTRIBUTE * 2)(
                CK_ATTRIBUTE(CKA_ID, ctypes.cast(encoded_id, CK_VOID_PTR), 2),
                CK_ATTRIBUTE(
                    CKA_CLASS,
                    ctypes.cast(ctypes.byref(encoded_class), CK_VOID_PTR),
                    ctypes.sizeof(encoded_class),
                ),
            )
            self.assertEqual(
                self.lib.C_FindObjectsInit(session, template, len(template)), CKR_OK
            )
            handle = CK_ULONG()
            found = CK_ULONG()
            self.assertEqual(
                self.lib.C_FindObjects(
                    session, ctypes.byref(handle), 1, ctypes.byref(found)
                ),
                CKR_OK,
            )
            self.assertEqual(found.value, 1)
            self.assertEqual(self.lib.C_FindObjectsFinal(session), CKR_OK)
            return handle.value

        def scalars(handle: int, *attribute_types: int) -> tuple[int, ...]:
            values = [CK_ULONG() for _ in attribute_types]
            attributes = (CK_ATTRIBUTE * len(attribute_types))(
                *[
                    CK_ATTRIBUTE(
                        attribute_type,
                        ctypes.cast(ctypes.byref(value), CK_VOID_PTR),
                        ctypes.sizeof(value),
                    )
                    for attribute_type, value in zip(attribute_types, values)
                ]
            )
            self.assertEqual(
                self.lib.C_GetAttributeValue(
                    session, handle, attributes, len(attributes)
                ),
                CKR_OK,
            )
            return tuple(value.value for value in values)

        ccm = find_one(8, CKO_SECRET_KEY)
        self.assertEqual(
            scalars(
                ccm,
                CKA_KEY_TYPE,
                CKA_VALUE_LEN,
                CKA_ENCRYPT,
                CKA_DECRYPT,
                CKA_WRAP,
                CKA_UNWRAP,
            ),
            (CKK_YUBICO_AES128_CCM_WRAP, 16, 1, 1, 1, 1),
        )

        rsa_private = find_one(9, CKO_PRIVATE_KEY)
        self.assertEqual(
            scalars(
                rsa_private,
                CKA_KEY_TYPE,
                CKA_ENCRYPT,
                CKA_DECRYPT,
                CKA_SIGN,
                CKA_WRAP,
                CKA_UNWRAP,
            ),
            (CKK_RSA, 0, 0, 0, 1, 1),
        )
        rsa_public = find_one(9, CKO_PUBLIC_KEY)
        self.assertEqual(
            scalars(
                rsa_public,
                CKA_KEY_TYPE,
                CKA_MODULUS_BITS,
                CKA_ENCRYPT,
                CKA_VERIFY,
                CKA_WRAP,
                CKA_UNWRAP,
            ),
            (CKK_RSA, 2048, 0, 0, 0, 0),
        )

        public_wrap = find_one(10, CKO_PUBLIC_KEY)
        self.assertEqual(
            scalars(
                public_wrap,
                CKA_KEY_TYPE,
                CKA_MODULUS_BITS,
                CKA_ENCRYPT,
                CKA_VERIFY,
                CKA_WRAP,
                CKA_UNWRAP,
            ),
            (CKK_RSA, 2048, 0, 0, 1, 0),
        )

    def test_abi_yubihsm_opaque_objects_match_reference_attributes(self) -> None:
        self.assertEqual(self.lib.C_Initialize(None), CKR_OK)
        session = self.open_slot_session(ABI_TEST_YUBIHSM_SLOT_ID)
        self.login_session(session)

        def find_by_id(object_id: int) -> int:
            encoded_id = (CK_BYTE * 2)(0, object_id)
            template = (CK_ATTRIBUTE * 1)(
                CK_ATTRIBUTE(
                    CKA_ID, ctypes.cast(encoded_id, CK_VOID_PTR), len(encoded_id)
                )
            )
            self.assertEqual(
                self.lib.C_FindObjectsInit(session, template, len(template)), CKR_OK
            )
            handle = CK_ULONG()
            found = CK_ULONG()
            self.assertEqual(
                self.lib.C_FindObjects(
                    session, ctypes.byref(handle), 1, ctypes.byref(found)
                ),
                CKR_OK,
            )
            self.assertEqual(found.value, 1)
            self.assertEqual(self.lib.C_FindObjectsFinal(session), CKR_OK)
            return handle.value

        def scalar_attribute(handle: int, attribute_type: int, value: object) -> int:
            attribute = CK_ATTRIBUTE(
                attribute_type,
                ctypes.cast(ctypes.byref(value), CK_VOID_PTR),
                ctypes.sizeof(value),
            )
            self.assertEqual(
                self.lib.C_GetAttributeValue(
                    session, handle, ctypes.byref(attribute), 1
                ),
                CKR_OK,
            )
            return value.value

        def bytes_attribute(handle: int, attribute_type: int) -> bytes:
            attribute = CK_ATTRIBUTE(attribute_type, None, 0)
            self.assertEqual(
                self.lib.C_GetAttributeValue(
                    session, handle, ctypes.byref(attribute), 1
                ),
                CKR_OK,
            )
            if attribute.ulValueLen == 0:
                return b""
            value = (CK_BYTE * attribute.ulValueLen)()
            attribute.pValue = ctypes.cast(value, CK_VOID_PTR)
            self.assertEqual(
                self.lib.C_GetAttributeValue(
                    session, handle, ctypes.byref(attribute), 1
                ),
                CKR_OK,
            )
            return bytes(value)

        data = find_by_id(5)
        self.assertEqual(scalar_attribute(data, CKA_CLASS, CK_ULONG()), CKO_DATA)
        self.assertEqual(bytes_attribute(data, CKA_APPLICATION), b"Opaque object")
        self.assertEqual(bytes_attribute(data, CKA_OBJECT_ID), b"")
        self.assertEqual(bytes_attribute(data, CKA_VALUE), b"ABI opaque data")
        for attribute_type, expected in [
            (CKA_TOKEN, 1),
            (CKA_PRIVATE, 0),
            (CKA_SENSITIVE, 0),
            (CKA_MODIFIABLE, 0),
            (CKA_COPYABLE, 0),
            (CKA_DESTROYABLE, 1),
        ]:
            self.assertEqual(
                scalar_attribute(data, attribute_type, CK_BYTE()), expected
            )

        certificate = find_by_id(6)
        self.assertEqual(
            scalar_attribute(certificate, CKA_CLASS, CK_ULONG()), CKO_CERTIFICATE
        )
        self.assertEqual(
            scalar_attribute(certificate, CKA_CERTIFICATE_TYPE, CK_ULONG()),
            CKC_X_509,
        )
        self.assertEqual(
            bytes_attribute(certificate, CKA_VALUE), b"\x30\x03\x02\x01\x01"
        )
        for attribute_type in (CKA_SUBJECT, CKA_ISSUER, CKA_SERIAL_NUMBER):
            self.assertEqual(bytes_attribute(certificate, attribute_type), b"")

    def test_legacy_function_list_entries_are_present(self) -> None:
        function_list = ctypes.POINTER(CK_FUNCTION_LIST)()

        self.assertEqual(self.lib.C_GetFunctionList(ctypes.byref(function_list)), CKR_OK)
        self.assertTrue(function_list)
        self.assertEqual(function_list.contents.version.major, 2)
        self.assertEqual(function_list.contents.version.minor, 40)
        self.assert_function_entries_present(function_list.contents, LEGACY_FUNCTIONS)

    def test_3_2_interface_function_list_entries_are_present(self) -> None:
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

    def test_initialize_validates_mutex_callback_configuration(self) -> None:
        partial_callbacks = CK_C_INITIALIZE_ARGS()
        partial_callbacks.CreateMutex = ctypes.c_void_p(1)
        self.assertEqual(
            self.lib.C_Initialize(ctypes.byref(partial_callbacks)),
            CKR_ARGUMENTS_BAD,
        )

        os_locking = CK_C_INITIALIZE_ARGS()
        os_locking.flags = CKF_OS_LOCKING_OK
        self.assertEqual(self.lib.C_Initialize(ctypes.byref(os_locking)), CKR_OK)
        self.assertEqual(self.lib.C_Finalize(None), CKR_OK)

        callbacks = CK_C_INITIALIZE_ARGS()
        callbacks.CreateMutex = ctypes.c_void_p(1)
        callbacks.DestroyMutex = ctypes.c_void_p(1)
        callbacks.LockMutex = ctypes.c_void_p(1)
        callbacks.UnlockMutex = ctypes.c_void_p(1)
        self.assertEqual(self.lib.C_Initialize(ctypes.byref(callbacks)), CKR_CANT_LOCK)

        callbacks.flags = CKF_OS_LOCKING_OK
        self.assertEqual(self.lib.C_Initialize(ctypes.byref(callbacks)), CKR_OK)
        self.assertEqual(self.lib.C_Finalize(None), CKR_OK)

        callbacks.flags = 1 << 31
        self.assertEqual(
            self.lib.C_Initialize(ctypes.byref(callbacks)),
            CKR_ARGUMENTS_BAD,
        )

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

    def test_open_session_validates_session_flags(self) -> None:
        session = CK_ULONG(-1)
        self.assertEqual(
            self.lib.C_OpenSession(ABI_TEST_SLOT_ID, 0, None, None, ctypes.byref(session)),
            CKR_CRYPTOKI_NOT_INITIALIZED,
        )

        self.assertEqual(self.lib.C_Initialize(None), CKR_OK)
        self.assertEqual(
            self.lib.C_OpenSession(ABI_TEST_SLOT_ID, 0, None, None, ctypes.byref(session)),
            CKR_SESSION_PARALLEL_NOT_SUPPORTED,
        )
        self.assertEqual(session.value, CK_ULONG(-1).value)
        self.assertEqual(
            self.lib.C_OpenSession(
                ABI_TEST_SLOT_ID,
                CKF_SERIAL_SESSION | CKF_ASYNC_SESSION,
                None,
                None,
                ctypes.byref(session),
            ),
            CKR_SESSION_ASYNC_NOT_SUPPORTED,
        )
        self.assertEqual(session.value, CK_ULONG(-1).value)

        for flags in (CKF_SERIAL_SESSION, CKF_SERIAL_SESSION | CKF_RW_SESSION):
            self.assertEqual(
                self.lib.C_OpenSession(
                    ABI_TEST_SLOT_ID,
                    flags,
                    None,
                    None,
                    ctypes.byref(session),
                ),
                CKR_OK,
            )
            self.assertNotEqual(session.value, CK_ULONG(-1).value)
            self.assertEqual(self.lib.C_CloseSession(session.value), CKR_OK)
            session.value = CK_ULONG(-1).value

    def test_mechanism_list_and_info_report_supported_mechanisms(self) -> None:
        self.assertEqual(self.lib.C_Initialize(None), CKR_OK)
        expected = [
            CKM_RSA_PKCS_KEY_PAIR_GEN,
            CKM_RSA_PKCS,
            CKM_EC_KEY_PAIR_GEN,
            CKM_ECDSA,
            CKM_GENERIC_SECRET_KEY_GEN,
        ]
        count = CK_ULONG()
        self.assertEqual(
            self.lib.C_GetMechanismList(ABI_TEST_SLOT_ID, None, ctypes.byref(count)),
            CKR_OK,
        )
        self.assertEqual(count.value, len(expected))

        mechanisms = (CK_ULONG * count.value)()
        self.assertEqual(
            self.lib.C_GetMechanismList(
                ABI_TEST_SLOT_ID,
                mechanisms,
                ctypes.byref(count),
            ),
            CKR_OK,
        )
        self.assertEqual(list(mechanisms), expected)

        info = CK_MECHANISM_INFO()
        self.assertEqual(
            self.lib.C_GetMechanismInfo(
                ABI_TEST_SLOT_ID,
                CKM_GENERIC_SECRET_KEY_GEN,
                ctypes.byref(info),
            ),
            CKR_OK,
        )
        self.assertEqual((info.ulMinKeySize, info.ulMaxKeySize), (1, 4096))
        self.assertEqual(info.flags & CKF_GENERATE, CKF_GENERATE)

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

    def test_generate_random_succeeds_for_open_session(self) -> None:
        session = self.initialize_and_open_session()
        random_data = (CK_BYTE * 32)()
        self.assertEqual(
            self.lib.C_GenerateRandom(session, random_data, len(random_data)),
            CKR_OK,
        )
        self.assertNotEqual(bytes(random_data), bytes(len(random_data)))

    def test_find_objects_validates_session_handles(self) -> None:
        self.assertEqual(self.lib.C_Initialize(None), CKR_OK)
        count = CK_ULONG()

        self.assertEqual(
            self.lib.C_FindObjectsInit(999, None, 0),
            CKR_SESSION_HANDLE_INVALID,
        )
        self.assertEqual(
            self.lib.C_FindObjects(999, None, 0, ctypes.byref(count)),
            CKR_SESSION_HANDLE_INVALID,
        )
        self.assertEqual(
            self.lib.C_FindObjectsFinal(999),
            CKR_SESSION_HANDLE_INVALID,
        )

    def test_find_objects_matches_empty_attributes_exactly(self) -> None:
        session = self.initialize_and_open_session()
        key_class = CK_ULONG(CKO_SECRET_KEY)
        key_type = CK_ULONG(CKK_GENERIC_SECRET)
        value = (CK_BYTE * 16)(*range(16))
        create_template = (CK_ATTRIBUTE * 3)(
            CK_ATTRIBUTE(
                CKA_CLASS,
                ctypes.cast(ctypes.byref(key_class), CK_VOID_PTR),
                ctypes.sizeof(key_class),
            ),
            CK_ATTRIBUTE(
                CKA_KEY_TYPE,
                ctypes.cast(ctypes.byref(key_type), CK_VOID_PTR),
                ctypes.sizeof(key_type),
            ),
            CK_ATTRIBUTE(CKA_VALUE, ctypes.cast(value, CK_VOID_PTR), len(value)),
        )
        empty_label_object = CK_ULONG()
        self.assertEqual(
            self.lib.C_CreateObject(
                session,
                create_template,
                len(create_template),
                ctypes.byref(empty_label_object),
            ),
            CKR_OK,
        )

        empty_label_template = (CK_ATTRIBUTE * 1)(
            CK_ATTRIBUTE(CKA_LABEL, None, 0)
        )
        self.assertEqual(
            self.lib.C_FindObjectsInit(
                session,
                empty_label_template,
                len(empty_label_template),
            ),
            CKR_OK,
        )
        objects = (CK_ULONG * 3)()
        count = CK_ULONG()
        self.assertEqual(
            self.lib.C_FindObjects(
                session,
                objects,
                len(objects),
                ctypes.byref(count),
            ),
            CKR_OK,
        )
        self.assertEqual(count.value, 1)
        self.assertEqual(objects[0], empty_label_object.value)
        self.assertEqual(self.lib.C_FindObjectsFinal(session), CKR_OK)

        empty_label_template[0].ulValueLen = 1
        self.assertEqual(
            self.lib.C_FindObjectsInit(
                session,
                empty_label_template,
                len(empty_label_template),
            ),
            CKR_ARGUMENTS_BAD,
        )
        self.assertEqual(
            self.lib.C_FindObjects(
                session,
                objects,
                len(objects),
                ctypes.byref(count),
            ),
            CKR_OPERATION_NOT_INITIALIZED,
        )

    def test_login_controls_private_object_visibility_and_signing(self) -> None:
        pin = (CK_BYTE * 4)(*b"1234")
        self.assertEqual(
            self.lib.C_Login(1, CKU_USER, pin, len(pin)),
            CKR_CRYPTOKI_NOT_INITIALIZED,
        )
        session = self.initialize_and_open_session()
        self.assertEqual(
            self.lib.C_Login(999, CKU_USER, pin, len(pin)),
            CKR_SESSION_HANDLE_INVALID,
        )
        info = CK_SESSION_INFO()
        self.assertEqual(
            self.lib.C_GetSessionInfo(session, ctypes.byref(info)),
            CKR_OK,
        )
        self.assertEqual(info.state, CKS_RO_PUBLIC_SESSION)

        key_class = CK_ULONG(CKO_PRIVATE_KEY)
        private_template = (CK_ATTRIBUTE * 1)(
            CK_ATTRIBUTE(
                CKA_CLASS,
                ctypes.cast(ctypes.byref(key_class), CK_VOID_PTR),
                ctypes.sizeof(key_class),
            )
        )
        found = CK_ULONG()
        found_count = CK_ULONG()
        self.assertEqual(
            self.lib.C_FindObjectsInit(session, private_template, len(private_template)),
            CKR_OK,
        )
        self.assertEqual(
            self.lib.C_FindObjects(
                session,
                ctypes.byref(found),
                1,
                ctypes.byref(found_count),
            ),
            CKR_OK,
        )
        self.assertEqual(found_count.value, 0)
        self.assertEqual(self.lib.C_FindObjectsFinal(session), CKR_OK)
        object_size = CK_ULONG()
        self.assertEqual(
            self.lib.C_GetObjectSize(session, 2, ctypes.byref(object_size)),
            CKR_OBJECT_HANDLE_INVALID,
        )

        mechanism = CK_MECHANISM(CKM_RSA_PKCS, None, 0)
        self.assertEqual(
            self.lib.C_SignInit(session, ctypes.byref(mechanism), 2),
            CKR_USER_NOT_LOGGED_IN,
        )

        bad_pin = (CK_BYTE * 4)(*b"9999")
        self.assertEqual(
            self.lib.C_Login(session, CKU_SO, pin, len(pin)),
            CKR_USER_TYPE_INVALID,
        )
        self.assertEqual(
            self.lib.C_Login(session, CKU_USER, bad_pin, len(bad_pin)),
            CKR_PIN_INCORRECT,
        )
        self.assertEqual(
            self.lib.C_Login(session, CKU_USER, pin, len(pin)),
            CKR_OK,
        )
        self.assertEqual(
            self.lib.C_Login(session, CKU_USER, pin, len(pin)),
            CKR_USER_ALREADY_LOGGED_IN,
        )
        self.assertEqual(
            self.lib.C_GetSessionInfo(session, ctypes.byref(info)),
            CKR_OK,
        )
        self.assertEqual(info.state, CKS_RO_USER_FUNCTIONS)

        self.assertEqual(
            self.lib.C_FindObjectsInit(session, private_template, len(private_template)),
            CKR_OK,
        )
        self.assertEqual(
            self.lib.C_FindObjects(
                session,
                ctypes.byref(found),
                1,
                ctypes.byref(found_count),
            ),
            CKR_OK,
        )
        self.assertEqual((found_count.value, found.value), (1, 2))
        self.assertEqual(self.lib.C_FindObjectsFinal(session), CKR_OK)
        self.assertEqual(
            self.lib.C_SignInit(session, ctypes.byref(mechanism), 2),
            CKR_OK,
        )

        self.assertEqual(self.lib.C_Logout(session), CKR_OK)
        self.assertEqual(
            self.lib.C_GetSessionInfo(session, ctypes.byref(info)),
            CKR_OK,
        )
        self.assertEqual(info.state, CKS_RO_PUBLIC_SESSION)
        self.assertEqual(self.lib.C_Logout(session), CKR_USER_NOT_LOGGED_IN)

        data = (CK_BYTE * 1)(1)
        signature_len = CK_ULONG()
        self.assertEqual(
            self.lib.C_Sign(
                session,
                data,
                len(data),
                None,
                ctypes.byref(signature_len),
            ),
            CKR_OPERATION_NOT_INITIALIZED,
        )

    def test_login_is_shared_and_logout_invalidates_private_objects(self) -> None:
        self.assertEqual(self.lib.C_Initialize(None), CKR_OK)
        read_only_session = CK_ULONG()
        read_write_session = CK_ULONG()
        self.assertEqual(
            self.lib.C_OpenSession(
                ABI_TEST_SLOT_ID,
                CKF_SERIAL_SESSION,
                None,
                None,
                ctypes.byref(read_only_session),
            ),
            CKR_OK,
        )
        self.assertEqual(
            self.lib.C_OpenSession(
                ABI_TEST_SLOT_ID,
                CKF_SERIAL_SESSION | CKF_RW_SESSION,
                None,
                None,
                ctypes.byref(read_write_session),
            ),
            CKR_OK,
        )

        pin = (CK_BYTE * 4)(*b"1234")
        self.assertEqual(
            self.lib.C_Login(read_only_session.value, CKU_USER, pin, len(pin)),
            CKR_OK,
        )
        self.assertEqual(
            self.lib.C_Login(read_write_session.value, CKU_USER, pin, len(pin)),
            CKR_USER_ALREADY_LOGGED_IN,
        )

        read_only_info = CK_SESSION_INFO()
        read_write_info = CK_SESSION_INFO()
        self.assertEqual(
            self.lib.C_GetSessionInfo(
                read_only_session.value,
                ctypes.byref(read_only_info),
            ),
            CKR_OK,
        )
        self.assertEqual(
            self.lib.C_GetSessionInfo(
                read_write_session.value,
                ctypes.byref(read_write_info),
            ),
            CKR_OK,
        )
        self.assertEqual(read_only_info.state, CKS_RO_USER_FUNCTIONS)
        self.assertEqual(read_write_info.state, CKS_RW_USER_FUNCTIONS)

        signing_mechanism = CK_MECHANISM(CKM_RSA_PKCS, None, 0)
        self.assertEqual(
            self.lib.C_SignInit(
                read_only_session.value,
                ctypes.byref(signing_mechanism),
                2,
            ),
            CKR_OK,
        )

        generation_mechanism = CK_MECHANISM(CKM_GENERIC_SECRET_KEY_GEN, None, 0)
        value_len = CK_ULONG(16)
        private_true = CK_BYTE(1)
        private_template = (CK_ATTRIBUTE * 2)(
            CK_ATTRIBUTE(
                CKA_VALUE_LEN,
                ctypes.cast(ctypes.byref(value_len), CK_VOID_PTR),
                ctypes.sizeof(value_len),
            ),
            CK_ATTRIBUTE(
                CKA_PRIVATE,
                ctypes.cast(ctypes.byref(private_true), CK_VOID_PTR),
                ctypes.sizeof(private_true),
            ),
        )
        private_session_key = CK_ULONG()
        self.assertEqual(
            self.lib.C_GenerateKey(
                read_write_session.value,
                ctypes.byref(generation_mechanism),
                private_template,
                len(private_template),
                ctypes.byref(private_session_key),
            ),
            CKR_OK,
        )

        self.assertEqual(self.lib.C_Logout(read_write_session.value), CKR_OK)
        self.assertEqual(
            self.lib.C_GetSessionInfo(
                read_only_session.value,
                ctypes.byref(read_only_info),
            ),
            CKR_OK,
        )
        self.assertEqual(
            self.lib.C_GetSessionInfo(
                read_write_session.value,
                ctypes.byref(read_write_info),
            ),
            CKR_OK,
        )
        self.assertEqual(read_only_info.state, CKS_RO_PUBLIC_SESSION)
        self.assertEqual(read_write_info.state, CKS_RW_PUBLIC_SESSION)

        data = (CK_BYTE * 1)(1)
        signature_len = CK_ULONG()
        self.assertEqual(
            self.lib.C_Sign(
                read_only_session.value,
                data,
                len(data),
                None,
                ctypes.byref(signature_len),
            ),
            CKR_OPERATION_NOT_INITIALIZED,
        )

        self.assertEqual(
            self.lib.C_Login(read_only_session.value, CKU_USER, pin, len(pin)),
            CKR_OK,
        )
        object_size = CK_ULONG()
        self.assertEqual(
            self.lib.C_GetObjectSize(
                read_only_session.value,
                2,
                ctypes.byref(object_size),
            ),
            CKR_OBJECT_HANDLE_INVALID,
        )
        self.assertEqual(
            self.lib.C_GetObjectSize(
                read_only_session.value,
                private_session_key.value,
                ctypes.byref(object_size),
            ),
            CKR_OBJECT_HANDLE_INVALID,
        )

        key_class = CK_ULONG(CKO_PRIVATE_KEY)
        find_template = (CK_ATTRIBUTE * 1)(
            CK_ATTRIBUTE(
                CKA_CLASS,
                ctypes.cast(ctypes.byref(key_class), CK_VOID_PTR),
                ctypes.sizeof(key_class),
            )
        )
        found = CK_ULONG()
        found_count = CK_ULONG()
        self.assertEqual(
            self.lib.C_FindObjectsInit(
                read_only_session.value,
                find_template,
                len(find_template),
            ),
            CKR_OK,
        )
        self.assertEqual(
            self.lib.C_FindObjects(
                read_only_session.value,
                ctypes.byref(found),
                1,
                ctypes.byref(found_count),
            ),
            CKR_OK,
        )
        self.assertEqual(found_count.value, 1)
        self.assertNotEqual(found.value, 2)
        self.assertNotEqual(found.value, private_session_key.value)
        self.assertEqual(
            self.lib.C_FindObjectsFinal(read_only_session.value),
            CKR_OK,
        )

    def test_authentication_survives_initiating_session_until_last_close(self) -> None:
        self.assertEqual(self.lib.C_Initialize(None), CKR_OK)
        first_session = CK_ULONG()
        second_session = CK_ULONG()
        for session in (first_session, second_session):
            self.assertEqual(
                self.lib.C_OpenSession(
                    ABI_TEST_SLOT_ID,
                    CKF_SERIAL_SESSION,
                    None,
                    None,
                    ctypes.byref(session),
                ),
                CKR_OK,
            )

        pin = (CK_BYTE * 4)(*b"1234")
        self.assertEqual(
            self.lib.C_Login(first_session.value, CKU_USER, pin, len(pin)),
            CKR_OK,
        )
        self.assertEqual(self.lib.C_CloseSession(first_session.value), CKR_OK)

        info = CK_SESSION_INFO()
        self.assertEqual(
            self.lib.C_GetSessionInfo(second_session.value, ctypes.byref(info)),
            CKR_OK,
        )
        self.assertEqual(info.state, CKS_RO_USER_FUNCTIONS)
        self.assertEqual(self.lib.C_CloseSession(second_session.value), CKR_OK)

        close_all_session = CK_ULONG()
        self.assertEqual(
            self.lib.C_OpenSession(
                ABI_TEST_SLOT_ID,
                CKF_SERIAL_SESSION,
                None,
                None,
                ctypes.byref(close_all_session),
            ),
            CKR_OK,
        )
        self.assertEqual(
            self.lib.C_Login(close_all_session.value, CKU_USER, pin, len(pin)),
            CKR_OK,
        )
        self.assertEqual(self.lib.C_CloseAllSessions(ABI_TEST_SLOT_ID), CKR_OK)

        public_session = CK_ULONG()
        self.assertEqual(
            self.lib.C_OpenSession(
                ABI_TEST_SLOT_ID,
                CKF_SERIAL_SESSION,
                None,
                None,
                ctypes.byref(public_session),
            ),
            CKR_OK,
        )
        self.assertEqual(
            self.lib.C_GetSessionInfo(public_session.value, ctypes.byref(info)),
            CKR_OK,
        )
        self.assertEqual(info.state, CKS_RO_PUBLIC_SESSION)

    def test_token_info_reports_current_session_counts(self) -> None:
        self.assertEqual(self.lib.C_Initialize(None), CKR_OK)
        read_only_session = CK_ULONG()
        read_write_session = CK_ULONG()
        self.assertEqual(
            self.lib.C_OpenSession(
                ABI_TEST_SLOT_ID,
                CKF_SERIAL_SESSION,
                None,
                None,
                ctypes.byref(read_only_session),
            ),
            CKR_OK,
        )
        self.assertEqual(
            self.lib.C_OpenSession(
                ABI_TEST_SLOT_ID,
                CKF_SERIAL_SESSION | CKF_RW_SESSION,
                None,
                None,
                ctypes.byref(read_write_session),
            ),
            CKR_OK,
        )

        info = CK_TOKEN_INFO()
        self.assertEqual(
            self.lib.C_GetTokenInfo(ABI_TEST_SLOT_ID, ctypes.byref(info)),
            CKR_OK,
        )
        self.assertEqual(info.ulMaxSessionCount, 0)
        self.assertEqual(info.ulSessionCount, 2)
        self.assertEqual(info.ulMaxRwSessionCount, 0)
        self.assertEqual(info.ulRwSessionCount, 1)
        self.assertEqual(info.ulTotalPublicMemory, CK_UNAVAILABLE_INFORMATION)
        self.assertEqual(info.ulFreePublicMemory, CK_UNAVAILABLE_INFORMATION)
        self.assertEqual(info.ulTotalPrivateMemory, CK_UNAVAILABLE_INFORMATION)
        self.assertEqual(info.ulFreePrivateMemory, CK_UNAVAILABLE_INFORMATION)

        self.assertEqual(self.lib.C_CloseSession(read_write_session.value), CKR_OK)
        self.assertEqual(
            self.lib.C_GetTokenInfo(ABI_TEST_SLOT_ID, ctypes.byref(info)),
            CKR_OK,
        )
        self.assertEqual(info.ulSessionCount, 1)
        self.assertEqual(info.ulRwSessionCount, 0)

    def test_read_only_sessions_cannot_mutate_token_or_private_objects(self) -> None:
        session = self.initialize_and_open_session()
        label = (CK_BYTE * len(b"read only"))(*b"read only")
        label_attribute = CK_ATTRIBUTE(
            CKA_LABEL,
            ctypes.cast(label, CK_VOID_PTR),
            len(label),
        )
        object_handle = CK_ULONG()

        self.assertEqual(
            self.lib.C_SetAttributeValue(
                session,
                1,
                ctypes.byref(label_attribute),
                1,
            ),
            CKR_SESSION_READ_ONLY,
        )
        self.assertEqual(
            self.lib.C_DestroyObject(session, 1),
            CKR_SESSION_READ_ONLY,
        )
        self.assertEqual(
            self.lib.C_CopyObject(session, 1, None, 0, ctypes.byref(object_handle)),
            CKR_SESSION_READ_ONLY,
        )

        key_class = CK_ULONG(CKO_SECRET_KEY)
        key_type = CK_ULONG(CKK_GENERIC_SECRET)
        token_true = CK_BYTE(1)
        token_false = CK_BYTE(0)
        private_true = CK_BYTE(1)
        private_false = CK_BYTE(0)
        value = (CK_BYTE * 16)(*range(16))
        base_template = (
            CK_ATTRIBUTE(
                CKA_CLASS,
                ctypes.cast(ctypes.byref(key_class), CK_VOID_PTR),
                ctypes.sizeof(key_class),
            ),
            CK_ATTRIBUTE(
                CKA_KEY_TYPE,
                ctypes.cast(ctypes.byref(key_type), CK_VOID_PTR),
                ctypes.sizeof(key_type),
            ),
            CK_ATTRIBUTE(CKA_VALUE, ctypes.cast(value, CK_VOID_PTR), len(value)),
        )
        token_object_template = (CK_ATTRIBUTE * 5)(
            *base_template,
            CK_ATTRIBUTE(
                CKA_TOKEN,
                ctypes.cast(ctypes.byref(token_true), CK_VOID_PTR),
                ctypes.sizeof(token_true),
            ),
            CK_ATTRIBUTE(
                CKA_PRIVATE,
                ctypes.cast(ctypes.byref(private_false), CK_VOID_PTR),
                ctypes.sizeof(private_false),
            ),
        )
        self.assertEqual(
            self.lib.C_CreateObject(
                session,
                token_object_template,
                len(token_object_template),
                ctypes.byref(object_handle),
            ),
            CKR_SESSION_READ_ONLY,
        )

        private_object_template = (CK_ATTRIBUTE * 5)(
            *base_template,
            CK_ATTRIBUTE(
                CKA_TOKEN,
                ctypes.cast(ctypes.byref(token_false), CK_VOID_PTR),
                ctypes.sizeof(token_false),
            ),
            CK_ATTRIBUTE(
                CKA_PRIVATE,
                ctypes.cast(ctypes.byref(private_true), CK_VOID_PTR),
                ctypes.sizeof(private_true),
            ),
        )
        self.assertEqual(
            self.lib.C_CreateObject(
                session,
                private_object_template,
                len(private_object_template),
                ctypes.byref(object_handle),
            ),
            CKR_USER_NOT_LOGGED_IN,
        )

        mechanism = CK_MECHANISM(CKM_GENERIC_SECRET_KEY_GEN, None, 0)
        value_len = CK_ULONG(16)
        token_key_template = (CK_ATTRIBUTE * 3)(
            CK_ATTRIBUTE(
                CKA_VALUE_LEN,
                ctypes.cast(ctypes.byref(value_len), CK_VOID_PTR),
                ctypes.sizeof(value_len),
            ),
            CK_ATTRIBUTE(
                CKA_TOKEN,
                ctypes.cast(ctypes.byref(token_true), CK_VOID_PTR),
                ctypes.sizeof(token_true),
            ),
            CK_ATTRIBUTE(
                CKA_PRIVATE,
                ctypes.cast(ctypes.byref(private_false), CK_VOID_PTR),
                ctypes.sizeof(private_false),
            ),
        )
        self.assertEqual(
            self.lib.C_GenerateKey(
                session,
                ctypes.byref(mechanism),
                token_key_template,
                len(token_key_template),
                ctypes.byref(object_handle),
            ),
            CKR_SESSION_READ_ONLY,
        )

        private_key_template = (CK_ATTRIBUTE * 3)(
            CK_ATTRIBUTE(
                CKA_VALUE_LEN,
                ctypes.cast(ctypes.byref(value_len), CK_VOID_PTR),
                ctypes.sizeof(value_len),
            ),
            CK_ATTRIBUTE(
                CKA_TOKEN,
                ctypes.cast(ctypes.byref(token_false), CK_VOID_PTR),
                ctypes.sizeof(token_false),
            ),
            CK_ATTRIBUTE(
                CKA_PRIVATE,
                ctypes.cast(ctypes.byref(private_true), CK_VOID_PTR),
                ctypes.sizeof(private_true),
            ),
        )
        self.assertEqual(
            self.lib.C_GenerateKey(
                session,
                ctypes.byref(mechanism),
                private_key_template,
                len(private_key_template),
                ctypes.byref(object_handle),
            ),
            CKR_USER_NOT_LOGGED_IN,
        )

        public_session_template = (CK_ATTRIBUTE * 3)(*base_template)
        self.assertEqual(
            self.lib.C_CreateObject(
                session,
                public_session_template,
                len(public_session_template),
                ctypes.byref(object_handle),
            ),
            CKR_OK,
        )
        self.assertEqual(
            self.lib.C_DestroyObject(session, object_handle.value),
            CKR_OK,
        )

    def test_sign_validates_state_and_session_handles(self) -> None:
        mechanism = CK_MECHANISM(CKM_RSA_PKCS, None, 0)
        data = (CK_BYTE * 4)(1, 2, 3, 4)
        signature_len = CK_ULONG()

        self.assertEqual(
            self.lib.C_SignInit(1, ctypes.byref(mechanism), 2),
            CKR_CRYPTOKI_NOT_INITIALIZED,
        )
        self.assertEqual(
            self.lib.C_Sign(1, data, len(data), None, ctypes.byref(signature_len)),
            CKR_CRYPTOKI_NOT_INITIALIZED,
        )
        self.assertEqual(
            self.lib.C_Sign(1, data, len(data), None, None),
            CKR_ARGUMENTS_BAD,
        )

        self.assertEqual(self.lib.C_Initialize(None), CKR_OK)
        self.assertEqual(
            self.lib.C_SignInit(999, ctypes.byref(mechanism), 2),
            CKR_SESSION_HANDLE_INVALID,
        )
        self.assertEqual(
            self.lib.C_Sign(999, data, len(data), None, ctypes.byref(signature_len)),
            CKR_SESSION_HANDLE_INVALID,
        )

    def test_verify_validates_state_and_session_handles(self) -> None:
        mechanism = CK_MECHANISM(CKM_RSA_PKCS, None, 0)
        data = (CK_BYTE * 4)(1, 2, 3, 4)
        signature = (CK_BYTE * 32)()

        self.assertEqual(
            self.lib.C_VerifyInit(1, ctypes.byref(mechanism), 1),
            CKR_CRYPTOKI_NOT_INITIALIZED,
        )
        self.assertEqual(
            self.lib.C_Verify(1, data, len(data), signature, len(signature)),
            CKR_CRYPTOKI_NOT_INITIALIZED,
        )

        self.assertEqual(self.lib.C_Initialize(None), CKR_OK)
        self.assertEqual(
            self.lib.C_VerifyInit(999, ctypes.byref(mechanism), 1),
            CKR_SESSION_HANDLE_INVALID,
        )
        self.assertEqual(
            self.lib.C_Verify(999, data, len(data), signature, len(signature)),
            CKR_SESSION_HANDLE_INVALID,
        )

    def test_sign_and_verify_rsa_pkcs_round_trip(self) -> None:
        session = self.initialize_and_open_session()
        self.login_session(session)
        mechanism = CK_MECHANISM(CKM_RSA_PKCS, None, 0)
        data = (CK_BYTE * 4)(1, 2, 3, 4)
        signature_len = CK_ULONG()

        self.assertEqual(self.lib.C_SignInit(session, ctypes.byref(mechanism), 2), CKR_OK)
        self.assertEqual(
            self.lib.C_Sign(session, data, len(data), None, ctypes.byref(signature_len)),
            CKR_OK,
        )
        self.assertEqual(signature_len.value, 256)

        signature = (CK_BYTE * signature_len.value)()
        self.assertEqual(
            self.lib.C_Sign(
                session,
                data,
                len(data),
                signature,
                ctypes.byref(signature_len),
            ),
            CKR_OK,
        )
        self.assertEqual(
            self.lib.C_Sign(
                session,
                data,
                len(data),
                signature,
                ctypes.byref(signature_len),
            ),
            CKR_OPERATION_NOT_INITIALIZED,
        )

        self.assertEqual(self.lib.C_VerifyInit(session, ctypes.byref(mechanism), 1), CKR_OK)
        self.assertEqual(
            self.lib.C_Verify(session, data, len(data), signature, signature_len.value),
            CKR_OK,
        )

        signature[0] ^= 0xFF
        self.assertEqual(self.lib.C_VerifyInit(session, ctypes.byref(mechanism), 1), CKR_OK)
        self.assertEqual(
            self.lib.C_Verify(session, data, len(data), signature, signature_len.value),
            CKR_SIGNATURE_INVALID,
        )

        short_signature = (CK_BYTE * 4)()
        self.assertEqual(self.lib.C_VerifyInit(session, ctypes.byref(mechanism), 1), CKR_OK)
        self.assertEqual(
            self.lib.C_Verify(
                session,
                data,
                len(data),
                short_signature,
                len(short_signature),
            ),
            CKR_SIGNATURE_LEN_RANGE,
        )
        self.assertEqual(self.lib.C_VerifyInit(session, ctypes.byref(mechanism), 1), CKR_OK)
        self.assertEqual(
            self.lib.C_Verify(
                session,
                None,
                1,
                signature,
                signature_len.value,
            ),
            CKR_ARGUMENTS_BAD,
        )
        self.assertEqual(
            self.lib.C_Verify(session, data, len(data), signature, signature_len.value),
            CKR_OPERATION_NOT_INITIALIZED,
        )

    def test_sign_and_verify_update_final_round_trip(self) -> None:
        session = self.initialize_and_open_session()
        self.login_session(session)
        mechanism = CK_MECHANISM(CKM_RSA_PKCS, None, 0)
        first = (CK_BYTE * 2)(*b"ab")
        second = (CK_BYTE * 2)(*b"cd")
        signature_len = CK_ULONG()

        self.assertEqual(self.lib.C_SignInit(session, ctypes.byref(mechanism), 2), CKR_OK)
        self.assertEqual(self.lib.C_SignUpdate(session, first, 2), CKR_OK)
        self.assertEqual(self.lib.C_SignUpdate(session, second, 2), CKR_OK)
        self.assertEqual(self.lib.C_SignFinal(session, None, ctypes.byref(signature_len)), CKR_OK)
        signature = (CK_BYTE * signature_len.value)()

        self.assertEqual(
            self.lib.C_SignFinal(session, signature, ctypes.byref(signature_len)),
            CKR_OK,
        )

        self.assertEqual(self.lib.C_VerifyInit(session, ctypes.byref(mechanism), 1), CKR_OK)
        self.assertEqual(self.lib.C_VerifyUpdate(session, first, 2), CKR_OK)
        self.assertEqual(self.lib.C_VerifyUpdate(session, second, 2), CKR_OK)
        self.assertEqual(
            self.lib.C_VerifyFinal(session, signature, signature_len.value),
            CKR_OK,
        )

    def test_sign_terminal_errors_clear_the_operation(self) -> None:
        session = self.initialize_and_open_session()
        self.login_session(session)
        mechanism = CK_MECHANISM(CKM_RSA_PKCS, None, 0)
        oversized_data = (CK_BYTE * 246)()
        signature_len = CK_ULONG()

        self.assertEqual(
            self.lib.C_SignInit(session, ctypes.byref(mechanism), 2),
            CKR_OK,
        )
        self.assertEqual(
            self.lib.C_Sign(
                session,
                oversized_data,
                len(oversized_data),
                None,
                ctypes.byref(signature_len),
            ),
            CKR_DATA_LEN_RANGE,
        )
        self.assertEqual(
            self.lib.C_Sign(
                session,
                oversized_data,
                len(oversized_data),
                None,
                ctypes.byref(signature_len),
            ),
            CKR_OPERATION_NOT_INITIALIZED,
        )

        data = (CK_BYTE * 1)(1)
        self.assertEqual(
            self.lib.C_SignInit(session, ctypes.byref(mechanism), 2),
            CKR_OK,
        )
        self.assertEqual(
            self.lib.C_Sign(session, data, len(data), None, None),
            CKR_ARGUMENTS_BAD,
        )
        self.assertEqual(
            self.lib.C_Sign(
                session,
                data,
                len(data),
                None,
                ctypes.byref(signature_len),
            ),
            CKR_OPERATION_NOT_INITIALIZED,
        )

    def test_generic_secret_key_is_rejected_for_rsa_signing(self) -> None:
        session = self.initialize_and_open_session()
        generate_mechanism = CK_MECHANISM(CKM_GENERIC_SECRET_KEY_GEN, None, 0)
        sign_value = CK_BYTE(1)
        value_len = CK_ULONG(32)
        template = (CK_ATTRIBUTE * 2)(
            CK_ATTRIBUTE(
                CKA_SIGN,
                ctypes.cast(ctypes.byref(sign_value), CK_VOID_PTR),
                ctypes.sizeof(sign_value),
            ),
            CK_ATTRIBUTE(
                CKA_VALUE_LEN,
                ctypes.cast(ctypes.byref(value_len), CK_VOID_PTR),
                ctypes.sizeof(value_len),
            ),
        )
        key = CK_ULONG()
        self.assertEqual(
            self.lib.C_GenerateKey(
                session,
                ctypes.byref(generate_mechanism),
                template,
                len(template),
                ctypes.byref(key),
            ),
            CKR_OK,
        )
        read_value_len = CK_ULONG()
        value_len_attribute = CK_ATTRIBUTE(
            CKA_VALUE_LEN,
            ctypes.cast(ctypes.byref(read_value_len), CK_VOID_PTR),
            ctypes.sizeof(read_value_len),
        )
        self.assertEqual(
            self.lib.C_GetAttributeValue(
                session,
                key.value,
                ctypes.byref(value_len_attribute),
                1,
            ),
            CKR_OK,
        )
        self.assertEqual(read_value_len.value, value_len.value)

        sensitive = CK_BYTE()
        extractable = CK_BYTE(0)
        always_sensitive = CK_BYTE()
        never_extractable = CK_BYTE()
        policy = (CK_ATTRIBUTE * 4)(
            CK_ATTRIBUTE(
                CKA_SENSITIVE,
                ctypes.cast(ctypes.byref(sensitive), CK_VOID_PTR),
                ctypes.sizeof(sensitive),
            ),
            CK_ATTRIBUTE(
                CKA_EXTRACTABLE,
                ctypes.cast(ctypes.byref(extractable), CK_VOID_PTR),
                ctypes.sizeof(extractable),
            ),
            CK_ATTRIBUTE(
                CKA_ALWAYS_SENSITIVE,
                ctypes.cast(ctypes.byref(always_sensitive), CK_VOID_PTR),
                ctypes.sizeof(always_sensitive),
            ),
            CK_ATTRIBUTE(
                CKA_NEVER_EXTRACTABLE,
                ctypes.cast(ctypes.byref(never_extractable), CK_VOID_PTR),
                ctypes.sizeof(never_extractable),
            ),
        )
        self.assertEqual(
            self.lib.C_GetAttributeValue(session, key.value, policy, len(policy)),
            CKR_OK,
        )
        self.assertEqual(
            (sensitive.value, extractable.value),
            (1, 0),
        )
        self.assertEqual(
            (always_sensitive.value, never_extractable.value),
            (1, 1),
        )

        unique_id = (CK_BYTE * 16)()
        local = CK_BYTE()
        key_gen_mechanism = CK_ULONG()
        provenance = (CK_ATTRIBUTE * 3)(
            CK_ATTRIBUTE(CKA_UNIQUE_ID, ctypes.cast(unique_id, CK_VOID_PTR), len(unique_id)),
            CK_ATTRIBUTE(
                CKA_LOCAL,
                ctypes.cast(ctypes.byref(local), CK_VOID_PTR),
                ctypes.sizeof(local),
            ),
            CK_ATTRIBUTE(
                CKA_KEY_GEN_MECHANISM,
                ctypes.cast(ctypes.byref(key_gen_mechanism), CK_VOID_PTR),
                ctypes.sizeof(key_gen_mechanism),
            ),
        )
        self.assertEqual(
            self.lib.C_GetAttributeValue(session, key.value, provenance, len(provenance)),
            CKR_OK,
        )
        self.assertTrue(bytes(unique_id[: provenance[0].ulValueLen]))
        self.assertEqual(local.value, 1)
        self.assertEqual(key_gen_mechanism.value, CKM_GENERIC_SECRET_KEY_GEN)

        value_attribute = CK_ATTRIBUTE(CKA_VALUE, None, 0)
        self.assertEqual(
            self.lib.C_GetAttributeValue(
                session,
                key.value,
                ctypes.byref(value_attribute),
                1,
            ),
            CKR_ATTRIBUTE_SENSITIVE,
        )
        self.assertEqual(value_attribute.ulValueLen, CK_ULONG(-1).value)

        rsa_mechanism = CK_MECHANISM(CKM_RSA_PKCS, None, 0)
        self.assertEqual(
            self.lib.C_SignInit(session, ctypes.byref(rsa_mechanism), key.value),
            CKR_KEY_TYPE_INCONSISTENT,
        )

    def test_generated_secret_key_enforces_sensitivity_policy(self) -> None:
        session = self.initialize_and_open_session()
        mechanism = CK_MECHANISM(CKM_GENERIC_SECRET_KEY_GEN, None, 0)
        value_len = CK_ULONG(24)
        sensitive = CK_BYTE(0)
        extractable = CK_BYTE(0)
        template = (CK_ATTRIBUTE * 3)(
            CK_ATTRIBUTE(
                CKA_VALUE_LEN,
                ctypes.cast(ctypes.byref(value_len), CK_VOID_PTR),
                ctypes.sizeof(value_len),
            ),
            CK_ATTRIBUTE(
                CKA_SENSITIVE,
                ctypes.cast(ctypes.byref(sensitive), CK_VOID_PTR),
                ctypes.sizeof(sensitive),
            ),
            CK_ATTRIBUTE(
                CKA_EXTRACTABLE,
                ctypes.cast(ctypes.byref(extractable), CK_VOID_PTR),
                ctypes.sizeof(extractable),
            ),
        )
        key = CK_ULONG()
        self.assertEqual(
            self.lib.C_GenerateKey(
                session,
                ctypes.byref(mechanism),
                template,
                len(template),
                ctypes.byref(key),
            ),
            CKR_OK,
        )

        value_attribute = CK_ATTRIBUTE(CKA_VALUE, None, 0)
        self.assertEqual(
            self.lib.C_GetAttributeValue(
                session,
                key.value,
                ctypes.byref(value_attribute),
                1,
            ),
            CKR_ATTRIBUTE_SENSITIVE,
        )
        self.assertEqual(value_attribute.ulValueLen, CK_UNAVAILABLE_INFORMATION)

        sensitive.value = 1
        extractable.value = 0
        harden = (CK_ATTRIBUTE * 2)(
            CK_ATTRIBUTE(
                CKA_SENSITIVE,
                ctypes.cast(ctypes.byref(sensitive), CK_VOID_PTR),
                ctypes.sizeof(sensitive),
            ),
            CK_ATTRIBUTE(
                CKA_EXTRACTABLE,
                ctypes.cast(ctypes.byref(extractable), CK_VOID_PTR),
                ctypes.sizeof(extractable),
            ),
        )
        self.assertEqual(
            self.lib.C_SetAttributeValue(session, key.value, harden, len(harden)),
            CKR_OK,
        )

        sensitive.value = 0
        self.assertEqual(
            self.lib.C_SetAttributeValue(session, key.value, ctypes.byref(harden[0]), 1),
            CKR_ATTRIBUTE_READ_ONLY,
        )
        extractable.value = 1
        self.assertEqual(
            self.lib.C_SetAttributeValue(session, key.value, ctypes.byref(harden[1]), 1),
            CKR_ATTRIBUTE_READ_ONLY,
        )

        always_sensitive = CK_BYTE(1)
        never_extractable = CK_BYTE(1)
        history = (CK_ATTRIBUTE * 2)(
            CK_ATTRIBUTE(
                CKA_ALWAYS_SENSITIVE,
                ctypes.cast(ctypes.byref(always_sensitive), CK_VOID_PTR),
                ctypes.sizeof(always_sensitive),
            ),
            CK_ATTRIBUTE(
                CKA_NEVER_EXTRACTABLE,
                ctypes.cast(ctypes.byref(never_extractable), CK_VOID_PTR),
                ctypes.sizeof(never_extractable),
            ),
        )
        self.assertEqual(
            self.lib.C_GetAttributeValue(session, key.value, history, len(history)),
            CKR_OK,
        )
        self.assertEqual(
            (always_sensitive.value, never_extractable.value),
            (0, 1),
        )

        value_attribute.pValue = None
        self.assertEqual(
            self.lib.C_GetAttributeValue(
                session,
                key.value,
                ctypes.byref(value_attribute),
                1,
            ),
            CKR_ATTRIBUTE_SENSITIVE,
        )

    def test_session_objects_are_isolated_and_removed_on_close(self) -> None:
        owner = self.initialize_and_open_session()
        other = CK_ULONG()
        self.assertEqual(
            self.lib.C_OpenSession(
                ABI_TEST_SLOT_ID,
                CKF_SERIAL_SESSION,
                None,
                None,
                ctypes.byref(other),
            ),
            CKR_OK,
        )

        mechanism = CK_MECHANISM(CKM_GENERIC_SECRET_KEY_GEN, None, 0)
        value_len = CK_ULONG(16)
        template = (CK_ATTRIBUTE * 1)(
            CK_ATTRIBUTE(
                CKA_VALUE_LEN,
                ctypes.cast(ctypes.byref(value_len), CK_VOID_PTR),
                ctypes.sizeof(value_len),
            )
        )
        key = CK_ULONG()
        self.assertEqual(
            self.lib.C_GenerateKey(
                owner,
                ctypes.byref(mechanism),
                template,
                len(template),
                ctypes.byref(key),
            ),
            CKR_OK,
        )
        key_class = CK_ULONG()
        attribute = CK_ATTRIBUTE(
            CKA_CLASS,
            ctypes.cast(ctypes.byref(key_class), CK_VOID_PTR),
            ctypes.sizeof(key_class),
        )
        self.assertEqual(
            self.lib.C_GetAttributeValue(owner, key.value, ctypes.byref(attribute), 1),
            CKR_OK,
        )
        self.assertEqual(key_class.value, CKO_SECRET_KEY)
        self.assertEqual(
            self.lib.C_GetAttributeValue(other.value, key.value, ctypes.byref(attribute), 1),
            CKR_OBJECT_HANDLE_INVALID,
        )

        self.assertEqual(self.lib.C_CloseSession(owner), CKR_OK)
        self.assertEqual(
            self.lib.C_GetAttributeValue(other.value, key.value, ctypes.byref(attribute), 1),
            CKR_OBJECT_HANDLE_INVALID,
        )

    def test_generate_key_requires_valid_value_length(self) -> None:
        session = self.initialize_and_open_session()
        mechanism = CK_MECHANISM(CKM_GENERIC_SECRET_KEY_GEN, None, 0)
        key = CK_ULONG()

        self.assertEqual(
            self.lib.C_GenerateKey(
                session,
                ctypes.byref(mechanism),
                None,
                0,
                ctypes.byref(key),
            ),
            CKR_TEMPLATE_INCOMPLETE,
        )

        for invalid_length in (0, 513):
            value_len = CK_ULONG(invalid_length)
            template = (CK_ATTRIBUTE * 1)(
                CK_ATTRIBUTE(
                    CKA_VALUE_LEN,
                    ctypes.cast(ctypes.byref(value_len), CK_VOID_PTR),
                    ctypes.sizeof(value_len),
                )
            )
            self.assertEqual(
                self.lib.C_GenerateKey(
                    session,
                    ctypes.byref(mechanism),
                    template,
                    len(template),
                    ctypes.byref(key),
                ),
                CKR_KEY_SIZE_RANGE,
            )

        value_len = CK_ULONG(16)
        value_len_attribute = CK_ATTRIBUTE(
            CKA_VALUE_LEN,
            ctypes.cast(ctypes.byref(value_len), CK_VOID_PTR),
            ctypes.sizeof(value_len),
        )
        duplicate_template = (CK_ATTRIBUTE * 2)(
            value_len_attribute,
            value_len_attribute,
        )
        self.assertEqual(
            self.lib.C_GenerateKey(
                session,
                ctypes.byref(mechanism),
                duplicate_template,
                len(duplicate_template),
                ctypes.byref(key),
            ),
            CKR_TEMPLATE_INCONSISTENT,
        )

    def test_get_attribute_value_validates_state_and_arguments(self) -> None:
        attr = CK_ATTRIBUTE(CKA_LABEL, None, 0)

        self.assertEqual(
            self.lib.C_GetAttributeValue(1, 1, ctypes.byref(attr), 1),
            CKR_CRYPTOKI_NOT_INITIALIZED,
        )

        self.assertEqual(self.lib.C_Initialize(None), CKR_OK)
        self.assertEqual(
            self.lib.C_GetAttributeValue(1, 1, None, 1),
            CKR_ARGUMENTS_BAD,
        )
        self.assertEqual(
            self.lib.C_GetAttributeValue(999, 1, ctypes.byref(attr), 1),
            CKR_SESSION_HANDLE_INVALID,
        )

    def test_set_attribute_value_validates_state_and_arguments(self) -> None:
        attr = CK_ATTRIBUTE(CKA_LABEL, None, 0)

        self.assertEqual(
            self.lib.C_SetAttributeValue(1, 1, ctypes.byref(attr), 1),
            CKR_CRYPTOKI_NOT_INITIALIZED,
        )

        self.assertEqual(self.lib.C_Initialize(None), CKR_OK)
        self.assertEqual(
            self.lib.C_SetAttributeValue(1, 1, None, 1),
            CKR_ARGUMENTS_BAD,
        )
        self.assertEqual(
            self.lib.C_SetAttributeValue(999, 1, ctypes.byref(attr), 1),
            CKR_SESSION_HANDLE_INVALID,
        )

    def test_destroy_object_validates_state_and_session(self) -> None:
        self.assertEqual(
            self.lib.C_DestroyObject(1, 1),
            CKR_CRYPTOKI_NOT_INITIALIZED,
        )

        self.assertEqual(self.lib.C_Initialize(None), CKR_OK)
        self.assertEqual(
            self.lib.C_DestroyObject(999, 1),
            CKR_SESSION_HANDLE_INVALID,
        )

    def test_create_object_validates_state_and_arguments(self) -> None:
        object_handle = CK_ULONG()

        self.assertEqual(
            self.lib.C_CreateObject(1, None, 0, ctypes.byref(object_handle)),
            CKR_CRYPTOKI_NOT_INITIALIZED,
        )

        self.assertEqual(self.lib.C_Initialize(None), CKR_OK)
        self.assertEqual(
            self.lib.C_CreateObject(1, None, 0, None),
            CKR_ARGUMENTS_BAD,
        )
        self.assertEqual(
            self.lib.C_CreateObject(1, None, 0, ctypes.byref(object_handle)),
            CKR_SESSION_HANDLE_INVALID,
        )
        self.assertEqual(
            self.lib.C_CreateObject(999, None, 0, ctypes.byref(object_handle)),
            CKR_SESSION_HANDLE_INVALID,
        )
        self.assertEqual(
            self.lib.C_CreateObject(999, None, 1, ctypes.byref(object_handle)),
            CKR_ARGUMENTS_BAD,
        )

    def test_object_lifecycle_succeeds_through_abi(self) -> None:
        session = self.initialize_and_open_session()
        key_class = CK_ULONG(CKO_SECRET_KEY)
        key_type = CK_ULONG(CKK_GENERIC_SECRET)
        label = (CK_BYTE * len(b"ABI object"))(*b"ABI object")
        value = (CK_BYTE * 16)(*range(16))
        template = (CK_ATTRIBUTE * 4)(
            CK_ATTRIBUTE(
                CKA_CLASS,
                ctypes.cast(ctypes.byref(key_class), CK_VOID_PTR),
                ctypes.sizeof(key_class),
            ),
            CK_ATTRIBUTE(
                CKA_KEY_TYPE,
                ctypes.cast(ctypes.byref(key_type), CK_VOID_PTR),
                ctypes.sizeof(key_type),
            ),
            CK_ATTRIBUTE(
                CKA_LABEL,
                ctypes.cast(label, CK_VOID_PTR),
                len(label),
            ),
            CK_ATTRIBUTE(CKA_VALUE, ctypes.cast(value, CK_VOID_PTR), len(value)),
        )
        object_handle = CK_ULONG()
        self.assertEqual(
            self.lib.C_CreateObject(
                session,
                template,
                len(template),
                ctypes.byref(object_handle),
            ),
            CKR_OK,
        )

        label_attribute = CK_ATTRIBUTE(CKA_LABEL, None, 0)
        self.assertEqual(
            self.lib.C_GetAttributeValue(
                session,
                object_handle.value,
                ctypes.byref(label_attribute),
                1,
            ),
            CKR_OK,
        )
        read_label = (CK_BYTE * label_attribute.ulValueLen)()
        label_attribute.pValue = ctypes.cast(read_label, CK_VOID_PTR)
        self.assertEqual(
            self.lib.C_GetAttributeValue(
                session,
                object_handle.value,
                ctypes.byref(label_attribute),
                1,
            ),
            CKR_OK,
        )
        self.assertEqual(bytes(read_label), b"ABI object")

        size = CK_ULONG()
        self.assertEqual(
            self.lib.C_GetObjectSize(session, object_handle.value, ctypes.byref(size)),
            CKR_OK,
        )
        self.assertGreater(size.value, len(label))

        renamed_label = (CK_BYTE * len(b"ABI renamed"))(*b"ABI renamed")
        rename_attribute = CK_ATTRIBUTE(
            CKA_LABEL,
            ctypes.cast(renamed_label, CK_VOID_PTR),
            len(renamed_label),
        )
        self.assertEqual(
            self.lib.C_SetAttributeValue(
                session,
                object_handle.value,
                ctypes.byref(rename_attribute),
                1,
            ),
            CKR_OK,
        )

        copied_label = (CK_BYTE * len(b"ABI copy"))(*b"ABI copy")
        copy_template = (CK_ATTRIBUTE * 1)(
            CK_ATTRIBUTE(
                CKA_LABEL,
                ctypes.cast(copied_label, CK_VOID_PTR),
                len(copied_label),
            )
        )
        copied_handle = CK_ULONG()
        self.assertEqual(
            self.lib.C_CopyObject(
                session,
                object_handle.value,
                copy_template,
                len(copy_template),
                ctypes.byref(copied_handle),
            ),
            CKR_OK,
        )

        original_unique_id = (CK_BYTE * 16)()
        copied_unique_id = (CK_BYTE * 16)()
        original_unique_attribute = CK_ATTRIBUTE(
            CKA_UNIQUE_ID,
            ctypes.cast(original_unique_id, CK_VOID_PTR),
            len(original_unique_id),
        )
        copied_unique_attribute = CK_ATTRIBUTE(
            CKA_UNIQUE_ID,
            ctypes.cast(copied_unique_id, CK_VOID_PTR),
            len(copied_unique_id),
        )
        self.assertEqual(
            self.lib.C_GetAttributeValue(
                session,
                object_handle.value,
                ctypes.byref(original_unique_attribute),
                1,
            ),
            CKR_OK,
        )
        self.assertEqual(
            self.lib.C_GetAttributeValue(
                session,
                copied_handle.value,
                ctypes.byref(copied_unique_attribute),
                1,
            ),
            CKR_OK,
        )
        self.assertNotEqual(
            bytes(original_unique_id[: original_unique_attribute.ulValueLen]),
            bytes(copied_unique_id[: copied_unique_attribute.ulValueLen]),
        )

        self.assertEqual(
            self.lib.C_FindObjectsInit(session, copy_template, len(copy_template)),
            CKR_OK,
        )
        found = CK_ULONG()
        found_count = CK_ULONG()
        self.assertEqual(
            self.lib.C_FindObjects(
                session,
                ctypes.byref(found),
                1,
                ctypes.byref(found_count),
            ),
            CKR_OK,
        )
        self.assertEqual((found_count.value, found.value), (1, copied_handle.value))
        self.assertEqual(self.lib.C_FindObjectsFinal(session), CKR_OK)

        self.assertEqual(self.lib.C_DestroyObject(session, object_handle.value), CKR_OK)
        self.assertEqual(self.lib.C_DestroyObject(session, copied_handle.value), CKR_OK)
        self.assertEqual(
            self.lib.C_GetObjectSize(session, copied_handle.value, ctypes.byref(size)),
            CKR_OBJECT_HANDLE_INVALID,
        )

    def test_object_templates_reject_duplicates_and_updates_are_atomic(self) -> None:
        self.assertEqual(self.lib.C_Initialize(None), CKR_OK)
        session = CK_ULONG()
        self.assertEqual(
            self.lib.C_OpenSession(
                ABI_TEST_SLOT_ID,
                CKF_SERIAL_SESSION | CKF_RW_SESSION,
                None,
                None,
                ctypes.byref(session),
            ),
            CKR_OK,
        )
        key_class = CK_ULONG(CKO_SECRET_KEY)
        duplicate_class = (CK_ATTRIBUTE * 2)(
            CK_ATTRIBUTE(
                CKA_CLASS,
                ctypes.cast(ctypes.byref(key_class), CK_VOID_PTR),
                ctypes.sizeof(key_class),
            ),
            CK_ATTRIBUTE(
                CKA_CLASS,
                ctypes.cast(ctypes.byref(key_class), CK_VOID_PTR),
                ctypes.sizeof(key_class),
            ),
        )
        handle = CK_ULONG()
        self.assertEqual(
            self.lib.C_CreateObject(
                session.value,
                duplicate_class,
                len(duplicate_class),
                ctypes.byref(handle),
            ),
            CKR_TEMPLATE_INCONSISTENT,
        )
        key_type = CK_ULONG(CKK_GENERIC_SECRET)
        incomplete = (CK_ATTRIBUTE * 2)(
            duplicate_class[0],
            CK_ATTRIBUTE(
                CKA_KEY_TYPE,
                ctypes.cast(ctypes.byref(key_type), CK_VOID_PTR),
                ctypes.sizeof(key_type),
            ),
        )
        self.assertEqual(
            self.lib.C_CreateObject(
                session.value,
                incomplete,
                len(incomplete),
                ctypes.byref(handle),
            ),
            CKR_TEMPLATE_INCOMPLETE,
        )

        new_label = (CK_BYTE * len(b"not committed"))(*b"not committed")
        update = (CK_ATTRIBUTE * 2)(
            CK_ATTRIBUTE(CKA_LABEL, ctypes.cast(new_label, CK_VOID_PTR), len(new_label)),
            duplicate_class[0],
        )
        self.assertEqual(
            self.lib.C_SetAttributeValue(session.value, 1, update, len(update)),
            CKR_ATTRIBUTE_READ_ONLY,
        )
        original_label = (CK_BYTE * len(b"Test RSA public key"))()
        label_attribute = CK_ATTRIBUTE(
            CKA_LABEL,
            ctypes.cast(original_label, CK_VOID_PTR),
            len(original_label),
        )
        self.assertEqual(
            self.lib.C_GetAttributeValue(
                session.value,
                1,
                ctypes.byref(label_attribute),
                1,
            ),
            CKR_OK,
        )
        self.assertEqual(bytes(original_label), b"Test RSA public key")

        duplicate_label = (CK_ATTRIBUTE * 2)(update[0], update[0])
        self.assertEqual(
            self.lib.C_CopyObject(
                session.value,
                1,
                duplicate_label,
                len(duplicate_label),
                ctypes.byref(handle),
            ),
            CKR_TEMPLATE_INCONSISTENT,
        )

        mechanism = CK_MECHANISM(CKM_GENERIC_SECRET_KEY_GEN, None, 0)
        value_len = CK_ULONG(16)
        generate_template = (CK_ATTRIBUTE * 3)(
            CK_ATTRIBUTE(
                CKA_VALUE_LEN,
                ctypes.cast(ctypes.byref(value_len), CK_VOID_PTR),
                ctypes.sizeof(value_len),
            ),
            update[0],
            update[0],
        )
        self.assertEqual(
            self.lib.C_GenerateKey(
                session.value,
                ctypes.byref(mechanism),
                generate_template,
                len(generate_template),
                ctypes.byref(handle),
            ),
            CKR_TEMPLATE_INCONSISTENT,
        )

    def test_copy_object_can_change_token_and_private_attributes(self) -> None:
        self.assertEqual(self.lib.C_Initialize(None), CKR_OK)
        session = CK_ULONG()
        self.assertEqual(
            self.lib.C_OpenSession(
                ABI_TEST_SLOT_ID,
                CKF_SERIAL_SESSION | CKF_RW_SESSION,
                None,
                None,
                ctypes.byref(session),
            ),
            CKR_OK,
        )
        self.login_session(session.value)

        token = CK_BYTE(0)
        private = CK_BYTE(1)
        template = (CK_ATTRIBUTE * 2)(
            CK_ATTRIBUTE(
                CKA_TOKEN,
                ctypes.cast(ctypes.byref(token), CK_VOID_PTR),
                ctypes.sizeof(token),
            ),
            CK_ATTRIBUTE(
                CKA_PRIVATE,
                ctypes.cast(ctypes.byref(private), CK_VOID_PTR),
                ctypes.sizeof(private),
            ),
        )
        copied = CK_ULONG()
        self.assertEqual(
            self.lib.C_CopyObject(
                session.value,
                1,
                template,
                len(template),
                ctypes.byref(copied),
            ),
            CKR_OK,
        )

        copied_token = CK_BYTE(1)
        copied_private = CK_BYTE(0)
        attributes = (CK_ATTRIBUTE * 2)(
            CK_ATTRIBUTE(
                CKA_TOKEN,
                ctypes.cast(ctypes.byref(copied_token), CK_VOID_PTR),
                ctypes.sizeof(copied_token),
            ),
            CK_ATTRIBUTE(
                CKA_PRIVATE,
                ctypes.cast(ctypes.byref(copied_private), CK_VOID_PTR),
                ctypes.sizeof(copied_private),
            ),
        )
        self.assertEqual(
            self.lib.C_GetAttributeValue(
                session.value,
                copied.value,
                attributes,
                len(attributes),
            ),
            CKR_OK,
        )
        self.assertEqual(copied_token.value, 0)
        self.assertEqual(copied_private.value, 1)

    def test_copy_object_validates_state_and_arguments(self) -> None:
        object_handle = CK_ULONG()

        self.assertEqual(
            self.lib.C_CopyObject(1, 1, None, 0, ctypes.byref(object_handle)),
            CKR_CRYPTOKI_NOT_INITIALIZED,
        )

        self.assertEqual(self.lib.C_Initialize(None), CKR_OK)
        self.assertEqual(
            self.lib.C_CopyObject(1, 1, None, 0, None),
            CKR_ARGUMENTS_BAD,
        )
        self.assertEqual(
            self.lib.C_CopyObject(1, 1, None, 0, ctypes.byref(object_handle)),
            CKR_SESSION_HANDLE_INVALID,
        )
        self.assertEqual(
            self.lib.C_CopyObject(999, 1, None, 1, ctypes.byref(object_handle)),
            CKR_ARGUMENTS_BAD,
        )

    def test_get_object_size_validates_state_and_arguments(self) -> None:
        size = CK_ULONG()

        self.assertEqual(
            self.lib.C_GetObjectSize(1, 1, ctypes.byref(size)),
            CKR_CRYPTOKI_NOT_INITIALIZED,
        )

        self.assertEqual(self.lib.C_Initialize(None), CKR_OK)
        self.assertEqual(
            self.lib.C_GetObjectSize(1, 1, None),
            CKR_ARGUMENTS_BAD,
        )
        self.assertEqual(
            self.lib.C_GetObjectSize(999, 1, ctypes.byref(size)),
            CKR_SESSION_HANDLE_INVALID,
        )

    def test_generate_key_validates_state_and_arguments(self) -> None:
        mechanism = CK_MECHANISM(CKM_GENERIC_SECRET_KEY_GEN, None, 0)
        key = CK_ULONG()

        self.assertEqual(
            self.lib.C_GenerateKey(1, ctypes.byref(mechanism), None, 0, ctypes.byref(key)),
            CKR_CRYPTOKI_NOT_INITIALIZED,
        )

        self.assertEqual(self.lib.C_Initialize(None), CKR_OK)
        self.assertEqual(
            self.lib.C_GenerateKey(1, None, None, 0, ctypes.byref(key)),
            CKR_ARGUMENTS_BAD,
        )
        self.assertEqual(
            self.lib.C_GenerateKey(1, ctypes.byref(mechanism), None, 0, None),
            CKR_ARGUMENTS_BAD,
        )
        self.assertEqual(
            self.lib.C_GenerateKey(999, ctypes.byref(mechanism), None, 0, ctypes.byref(key)),
            CKR_SESSION_HANDLE_INVALID,
        )
        unsupported = CK_MECHANISM(CKM_RSA_PKCS, None, 0)
        self.assertEqual(
            self.lib.C_GenerateKey(999, ctypes.byref(unsupported), None, 0, ctypes.byref(key)),
            CKR_SESSION_HANDLE_INVALID,
        )
        self.assertEqual(
            self.lib.C_GenerateKey(
                999,
                ctypes.byref(mechanism),
                None,
                1,
                ctypes.byref(key),
            ),
            CKR_ARGUMENTS_BAD,
        )

    def test_interface_list_reports_all_supported_interfaces(self) -> None:
        count = CK_ULONG()

        self.assertEqual(self.lib.C_GetInterfaceList(None, ctypes.byref(count)), CKR_OK)
        self.assertEqual(count.value, 4)

        interfaces = (CK_INTERFACE * count.value)()
        self.assertEqual(
            self.lib.C_GetInterfaceList(interfaces, ctypes.byref(count)),
            CKR_OK,
        )

        self.assertEqual(count.value, 4)
        versions = []
        for interface in interfaces:
            self.assertEqual(ctypes.string_at(interface.pInterfaceName), b"PKCS 11")
            self.assertTrue(interface.pFunctionList)
            self.assertEqual(interface.flags, 0)
            version = ctypes.cast(
                interface.pFunctionList,
                ctypes.POINTER(CK_VERSION),
            ).contents
            versions.append((version.major, version.minor))
        self.assertEqual(versions, [(2, 40), (3, 0), (3, 1), (3, 2)])

    def test_interface_list_checks_buffer_size(self) -> None:
        count = CK_ULONG(0)
        interface = CK_INTERFACE()

        self.assertEqual(
            self.lib.C_GetInterfaceList(ctypes.byref(interface), ctypes.byref(count)),
            CKR_BUFFER_TOO_SMALL,
        )
        self.assertEqual(count.value, 4)

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

        for name in (b"NOT PKCS", b"X"):
            self.assertEqual(
                self.lib.C_GetInterface(
                    name,
                    ctypes.byref(version),
                    ctypes.byref(interface),
                    0,
                ),
                CKR_ARGUMENTS_BAD,
            )

        self.assertEqual(
            self.lib.C_GetInterface(
                b"PKCS 11",
                ctypes.byref(version),
                ctypes.byref(interface),
                CKF_INTERFACE_FORK_SAFE,
            ),
            CKR_ARGUMENTS_BAD,
        )


if __name__ == "__main__":
    unittest.main()
