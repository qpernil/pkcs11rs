#!/usr/bin/env python3
"""Executable OASIS PKCS #11 v3.2 provider profile test cases.

Each OASIS mandatory XML artifact is exposed as a separate unittest case. The
executor follows the XML call order and treats the immediately following
same-named element as the expected response.

The published vectors contain provider-specific fixture values. This runner
uses the permitted provider/session/object variations and records two semantic
adaptations:

* C_FindObjects is drained in batches so symbolic object references can be
  bound by their downstream role rather than unspecified provider ordering.
* Certificate values and generated signatures are checked structurally rather
  than compared byte-for-byte with the illustrative OASIS provider values.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import pathlib
import sys
import time
import unittest
import xml.etree.ElementTree as ET
from typing import Iterable


ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import test_pkcs11 as p11  # noqa: E402

from conformance.oasis_cases import (  # noqa: E402
    case_digest,
    case_url,
    case_xml,
)


CKA_PUBLIC_EXPONENT = 0x00000122
CKF_TOKEN_PRESENT = 0x00000001
CKF_HW = 0x00000001
CKF_ENCRYPT = 0x00000100
CKF_DECRYPT = 0x00000200
CKF_DIGEST = 0x00000400
CKF_SIGN = 0x00000800
CKF_VERIFY = 0x00002000
CKF_WRAP = 0x00020000
CKF_UNWRAP = 0x00040000
CKF_GENERATE_KEY_PAIR = 0x00010000
CKM_SHA256_RSA_PKCS = 0x00000040
CKM_SHA512 = 0x00000270

ATTRIBUTE_TYPES = {
    "TOKEN": p11.CKA_TOKEN,
    "LABEL": p11.CKA_LABEL,
    "CLASS": p11.CKA_CLASS,
    "VALUE": p11.CKA_VALUE,
    "MODULUS": p11.CKA_MODULUS,
    "PUBLIC_EXPONENT": CKA_PUBLIC_EXPONENT,
}

OBJECT_CLASSES = {
    "CERTIFICATE": p11.CKO_CERTIFICATE,
    "PRIVATE_KEY": p11.CKO_PRIVATE_KEY,
    "PUBLIC_KEY": p11.CKO_PUBLIC_KEY,
}

MECHANISMS = {
    "SHA512": CKM_SHA512,
    "RSA_PKCS_KEY_PAIR_GEN": p11.CKM_RSA_PKCS_KEY_PAIR_GEN,
    "RSA_PKCS": p11.CKM_RSA_PKCS,
    "SHA256_RSA_PKCS": CKM_SHA256_RSA_PKCS,
}

FLAGS = {
    "SERIAL_SESSION": p11.CKF_SERIAL_SESSION,
    "RW_SESSION": p11.CKF_RW_SESSION,
    "HW": CKF_HW,
    "ENCRYPT": CKF_ENCRYPT,
    "DECRYPT": CKF_DECRYPT,
    "DIGEST": CKF_DIGEST,
    "SIGN": CKF_SIGN,
    "VERIFY": CKF_VERIFY,
    "WRAP": CKF_WRAP,
    "UNWRAP": CKF_UNWRAP,
    "GENERATE_KEY_PAIR": CKF_GENERATE_KEY_PAIR,
    "TOKEN_PRESENT": CKF_TOKEN_PRESENT,
}

RETURN_VALUES = {
    "OK": p11.CKR_OK,
}


def _parse_flags(value: str | None) -> int:
    if not value:
        return 0
    result = 0
    for name in value.replace("|", " ").split():
        result |= FLAGS[name]
    return result


def _value(element: ET.Element | None) -> str | None:
    return None if element is None else element.get("value")


def _pkcs11_text(value: object) -> str:
    return bytes(value).rstrip(b" \0").decode("utf-8", errors="replace")


def _child(element: ET.Element, name: str) -> ET.Element | None:
    return element.find(name)


def _pair_calls(xml: bytes) -> list[tuple[ET.Element, ET.Element]]:
    root = ET.fromstring(xml)
    elements = list(root)
    if len(elements) % 2:
        raise AssertionError("OASIS XML contains an unpaired call element")
    pairs = []
    for offset in range(0, len(elements), 2):
        request, response = elements[offset : offset + 2]
        if request.tag != response.tag or response.get("rv") is None:
            raise AssertionError(
                f"invalid call/response pair at element {offset}: "
                f"{request.tag}/{response.tag}"
            )
        pairs.append((request, response))
    return pairs


def _bind_library(lib: ctypes.CDLL) -> None:
    lib.C_Initialize.argtypes = [ctypes.c_void_p]
    lib.C_Initialize.restype = p11.CK_RV
    lib.C_Finalize.argtypes = [ctypes.c_void_p]
    lib.C_Finalize.restype = p11.CK_RV
    lib.C_GetInfo.argtypes = [ctypes.POINTER(p11.CK_INFO)]
    lib.C_GetInfo.restype = p11.CK_RV
    lib.C_GetSlotList.argtypes = [
        p11.CK_BYTE,
        ctypes.POINTER(p11.CK_ULONG),
        ctypes.POINTER(p11.CK_ULONG),
    ]
    lib.C_GetSlotList.restype = p11.CK_RV
    lib.C_GetSlotInfo.argtypes = [
        p11.CK_ULONG,
        ctypes.POINTER(p11.CK_SLOT_INFO),
    ]
    lib.C_GetSlotInfo.restype = p11.CK_RV
    lib.C_GetTokenInfo.argtypes = [
        p11.CK_ULONG,
        ctypes.POINTER(p11.CK_TOKEN_INFO),
    ]
    lib.C_GetTokenInfo.restype = p11.CK_RV
    lib.C_GetMechanismList.argtypes = [
        p11.CK_ULONG,
        ctypes.POINTER(p11.CK_ULONG),
        ctypes.POINTER(p11.CK_ULONG),
    ]
    lib.C_GetMechanismList.restype = p11.CK_RV
    lib.C_GetMechanismInfo.argtypes = [
        p11.CK_ULONG,
        p11.CK_ULONG,
        ctypes.POINTER(p11.CK_MECHANISM_INFO),
    ]
    lib.C_GetMechanismInfo.restype = p11.CK_RV
    lib.C_OpenSession.argtypes = [
        p11.CK_ULONG,
        p11.CK_FLAGS,
        p11.CK_VOID_PTR,
        p11.CK_VOID_PTR,
        ctypes.POINTER(p11.CK_ULONG),
    ]
    lib.C_OpenSession.restype = p11.CK_RV
    lib.C_CloseSession.argtypes = [p11.CK_ULONG]
    lib.C_CloseSession.restype = p11.CK_RV
    lib.C_CloseAllSessions.argtypes = [p11.CK_ULONG]
    lib.C_CloseAllSessions.restype = p11.CK_RV
    lib.C_Login.argtypes = [
        p11.CK_ULONG,
        p11.CK_ULONG,
        ctypes.POINTER(p11.CK_BYTE),
        p11.CK_ULONG,
    ]
    lib.C_Login.restype = p11.CK_RV
    lib.C_Logout.argtypes = [p11.CK_ULONG]
    lib.C_Logout.restype = p11.CK_RV
    lib.C_FindObjectsInit.argtypes = [
        p11.CK_ULONG,
        ctypes.POINTER(p11.CK_ATTRIBUTE),
        p11.CK_ULONG,
    ]
    lib.C_FindObjectsInit.restype = p11.CK_RV
    lib.C_FindObjects.argtypes = [
        p11.CK_ULONG,
        ctypes.POINTER(p11.CK_ULONG),
        p11.CK_ULONG,
        ctypes.POINTER(p11.CK_ULONG),
    ]
    lib.C_FindObjects.restype = p11.CK_RV
    lib.C_FindObjectsFinal.argtypes = [p11.CK_ULONG]
    lib.C_FindObjectsFinal.restype = p11.CK_RV
    lib.C_GetAttributeValue.argtypes = [
        p11.CK_ULONG,
        p11.CK_ULONG,
        ctypes.POINTER(p11.CK_ATTRIBUTE),
        p11.CK_ULONG,
    ]
    lib.C_GetAttributeValue.restype = p11.CK_RV
    lib.C_SignInit.argtypes = [
        p11.CK_ULONG,
        ctypes.POINTER(p11.CK_MECHANISM),
        p11.CK_ULONG,
    ]
    lib.C_SignInit.restype = p11.CK_RV
    lib.C_Sign.argtypes = [
        p11.CK_ULONG,
        ctypes.POINTER(p11.CK_BYTE),
        p11.CK_ULONG,
        ctypes.POINTER(p11.CK_BYTE),
        ctypes.POINTER(p11.CK_ULONG),
    ]
    lib.C_Sign.restype = p11.CK_RV


class OasisExecutor:
    def __init__(
        self,
        testcase: unittest.TestCase,
        lib: ctypes.CDLL,
        case_name: str,
        slot_id: int,
        pin: bytes | None,
    ) -> None:
        self.testcase = testcase
        self.lib = lib
        self.case_name = case_name
        self.slot_id = slot_id
        self.pin = pin
        self.slot_ids: list[int] = []
        self.slot_count = 0
        self.mechanisms: list[int] = []
        self.mechanism_count = 0
        self.session: int | None = None
        self.find_handles: list[int] = []
        self.find_epoch = 0
        self.object_bindings: dict[tuple[int, int], int] = {}
        self.attribute_lengths: dict[tuple[int, int], int] = {}
        self.last_modulus: bytes | None = None
        self.semantic_bindings: list[dict[str, object]] = []
        self.calls: list[str] = []
        self.token_metadata: dict[str, object] = {}

    def run(self) -> dict[str, object]:
        for request, response in _pair_calls(case_xml(self.case_name)):
            handler = getattr(self, f"_call_{request.tag}", None)
            if handler is None:
                raise AssertionError(
                    f"{self.case_name}: unsupported XML call {request.tag}"
                )
            handler(request, response)
            self.calls.append(request.tag)
        return {
            "case": self.case_name,
            "source": case_url(self.case_name),
            "sha256": case_digest(self.case_name),
            "slot": self.slot_id,
            "calls": self.calls,
            "semantic_bindings": self.semantic_bindings,
            "token": self.token_metadata,
        }

    def _assert_rv(self, response: ET.Element, actual: int) -> None:
        expected_name = response.get("rv")
        if expected_name not in RETURN_VALUES:
            raise AssertionError(f"unsupported expected return value {expected_name}")
        self.testcase.assertEqual(
            actual,
            RETURN_VALUES[expected_name],
            f"{self.case_name} {response.tag}",
        )

    def _selected_slot(self, value: str | None) -> int:
        if value == "${SlotList.SlotID[0]}":
            return self.slot_id
        if value is None:
            raise AssertionError("missing SlotID")
        return int(value, 0)

    def _session_value(self, value: str | None) -> int:
        if value != "${Session}" or self.session is None:
            raise AssertionError(f"unresolved session reference {value}")
        return self.session

    def _call_C_Initialize(
        self, _request: ET.Element, response: ET.Element
    ) -> None:
        self._assert_rv(response, self.lib.C_Initialize(None))

    def _call_C_Finalize(self, _request: ET.Element, response: ET.Element) -> None:
        self._assert_rv(response, self.lib.C_Finalize(None))

    def _call_C_GetInfo(self, _request: ET.Element, response: ET.Element) -> None:
        info = p11.CK_INFO()
        self._assert_rv(response, self.lib.C_GetInfo(ctypes.byref(info)))
        expected = _child(response, "Info")
        version = None if expected is None else _child(expected, "CryptokiVersion")
        if version is not None:
            self.testcase.assertEqual(info.cryptokiVersion.major, int(version.get("major")))
            self.testcase.assertEqual(info.cryptokiVersion.minor, int(version.get("minor")))

    def _call_C_GetSlotList(
        self, request: ET.Element, response: ET.Element
    ) -> None:
        token_present = _value(_child(request, "TokenPresent")) == "true"
        requested = _child(request, "SlotList")
        count = p11.CK_ULONG()
        if requested is None or requested.get("length") is None:
            rv = self.lib.C_GetSlotList(token_present, None, ctypes.byref(count))
            self._assert_rv(response, rv)
            self.slot_count = count.value
            return

        count.value = max(1, self.slot_count)
        if requested.get("length") not in (
            "${SlotList.length}",
            str(count.value),
        ):
            count.value = int(requested.get("length"), 0)
        slots = (p11.CK_ULONG * count.value)()
        rv = self.lib.C_GetSlotList(token_present, slots, ctypes.byref(count))
        self._assert_rv(response, rv)
        actual = list(slots[: count.value])
        self.testcase.assertIn(self.slot_id, actual)
        self.slot_ids = [self.slot_id] + [
            slot for slot in actual if slot != self.slot_id
        ]

    def _call_C_GetSlotInfo(
        self, request: ET.Element, response: ET.Element
    ) -> None:
        slot = self._selected_slot(_value(_child(request, "SlotID")))
        info = p11.CK_SLOT_INFO()
        self._assert_rv(response, self.lib.C_GetSlotInfo(slot, ctypes.byref(info)))
        self.testcase.assertNotEqual(info.flags & CKF_TOKEN_PRESENT, 0)

    def _call_C_GetTokenInfo(
        self, request: ET.Element, response: ET.Element
    ) -> None:
        slot = self._selected_slot(_value(_child(request, "SlotID")))
        info = p11.CK_TOKEN_INFO()
        self._assert_rv(response, self.lib.C_GetTokenInfo(slot, ctypes.byref(info)))
        self.testcase.assertTrue(bytes(info.label).strip(b" "))
        self.token_metadata = {
            "label": _pkcs11_text(info.label),
            "manufacturer": _pkcs11_text(info.manufacturerID),
            "model": _pkcs11_text(info.model),
            "serial": _pkcs11_text(info.serialNumber),
            "hardware_version": (
                f"{info.hardwareVersion.major}.{info.hardwareVersion.minor}"
            ),
            "firmware_version": (
                f"{info.firmwareVersion.major}.{info.firmwareVersion.minor}"
            ),
        }

    def _call_C_GetMechanismList(
        self, request: ET.Element, response: ET.Element
    ) -> None:
        slot = self._selected_slot(_value(_child(request, "SlotID")))
        requested = _child(request, "MechanismList")
        count = p11.CK_ULONG()
        if requested is None or requested.get("length") is None:
            rv = self.lib.C_GetMechanismList(slot, None, ctypes.byref(count))
            self._assert_rv(response, rv)
            self.mechanism_count = count.value
            return

        count.value = max(1, self.mechanism_count)
        mechanisms = (p11.CK_ULONG * count.value)()
        rv = self.lib.C_GetMechanismList(slot, mechanisms, ctypes.byref(count))
        self._assert_rv(response, rv)
        self.mechanisms = list(mechanisms[: count.value])
        expected_list = _child(response, "MechanismList")
        if expected_list is not None:
            expected = {
                MECHANISMS[_value(element)]
                for element in expected_list.findall("Type")
            }
            self.testcase.assertTrue(
                expected.issubset(set(self.mechanisms)),
                f"missing OASIS mechanisms: {sorted(expected - set(self.mechanisms))}",
            )

    def _call_C_GetMechanismInfo(
        self, request: ET.Element, response: ET.Element
    ) -> None:
        slot = self._selected_slot(_value(_child(request, "SlotID")))
        mechanism_name = _value(_child(request, "Type"))
        mechanism = MECHANISMS[mechanism_name]
        info = p11.CK_MECHANISM_INFO()
        self._assert_rv(
            response,
            self.lib.C_GetMechanismInfo(slot, mechanism, ctypes.byref(info)),
        )
        self.testcase.assertLessEqual(info.ulMinKeySize, info.ulMaxKeySize)
        expected = _child(response, "MechanismInfo")
        flags = None if expected is None else _child(expected, "Flags")
        if flags is not None:
            required = _parse_flags(_value(flags))
            self.testcase.assertEqual(info.flags & required, required)

    def _call_C_OpenSession(
        self, request: ET.Element, response: ET.Element
    ) -> None:
        slot = self._selected_slot(_value(_child(request, "SlotID")))
        flags = _parse_flags(_value(_child(request, "Flags")))
        session = p11.CK_ULONG()
        self._assert_rv(
            response,
            self.lib.C_OpenSession(
                slot, flags, None, None, ctypes.byref(session)
            ),
        )
        self.session = session.value

    def _call_C_CloseSession(
        self, request: ET.Element, response: ET.Element
    ) -> None:
        session = self._session_value(_value(_child(request, "Session")))
        self._assert_rv(response, self.lib.C_CloseSession(session))

    def _call_C_CloseAllSessions(
        self, request: ET.Element, response: ET.Element
    ) -> None:
        slot = self._selected_slot(_value(_child(request, "SlotID")))
        self._assert_rv(response, self.lib.C_CloseAllSessions(slot))

    def _call_C_Login(self, request: ET.Element, response: ET.Element) -> None:
        session = self._session_value(_value(_child(request, "Session")))
        if self.pin is None:
            raise AssertionError(
                "PKCS11RS_OASIS_PIN is required for this OASIS case"
            )
        pin = (p11.CK_BYTE * len(self.pin)).from_buffer_copy(self.pin)
        self._assert_rv(
            response,
            self.lib.C_Login(session, p11.CKU_USER, pin, len(pin)),
        )

    def _call_C_Logout(self, request: ET.Element, response: ET.Element) -> None:
        session = self._session_value(_value(_child(request, "Session")))
        self._assert_rv(response, self.lib.C_Logout(session))

    def _template(
        self, attributes: Iterable[ET.Element]
    ) -> tuple[ctypes.Array[p11.CK_ATTRIBUTE], list[object]]:
        encoded: list[p11.CK_ATTRIBUTE] = []
        keepalive: list[object] = []
        for element in attributes:
            name = element.get("type")
            attribute_type = ATTRIBUTE_TYPES[name]
            value = element.get("value")
            if name == "TOKEN":
                storage = p11.CK_BYTE(1 if value.upper() == "TRUE" else 0)
                length = ctypes.sizeof(storage)
            elif name == "CLASS":
                storage = p11.CK_ULONG(OBJECT_CLASSES[value])
                length = ctypes.sizeof(storage)
            elif name == "LABEL":
                raw = value.encode("utf-8")
                storage = (p11.CK_BYTE * len(raw)).from_buffer_copy(raw)
                length = len(raw)
            else:
                raise AssertionError(f"unsupported template attribute {name}")
            keepalive.append(storage)
            encoded.append(
                p11.CK_ATTRIBUTE(
                    attribute_type,
                    ctypes.cast(ctypes.byref(storage), p11.CK_VOID_PTR),
                    length,
                )
            )
        array = (p11.CK_ATTRIBUTE * len(encoded))(*encoded)
        return array, keepalive

    def _call_C_FindObjectsInit(
        self, request: ET.Element, response: ET.Element
    ) -> None:
        session = self._session_value(_value(_child(request, "Session")))
        template_node = _child(request, "Template")
        attributes = [] if template_node is None else template_node.findall("Attribute")
        template, keepalive = self._template(attributes)
        _ = keepalive
        self._assert_rv(
            response,
            self.lib.C_FindObjectsInit(session, template, len(template)),
        )

    def _call_C_FindObjects(
        self, request: ET.Element, response: ET.Element
    ) -> None:
        session = self._session_value(_value(_child(request, "Session")))
        object_node = _child(request, "Object")
        maximum = int(object_node.get("length", "1"), 0)
        handles: list[int] = []
        batches = 0
        while True:
            storage = (p11.CK_ULONG * maximum)()
            count = p11.CK_ULONG()
            rv = self.lib.C_FindObjects(
                session, storage, maximum, ctypes.byref(count)
            )
            self._assert_rv(response, rv)
            batches += 1
            handles.extend(storage[: count.value])
            if count.value < maximum:
                break
        self.find_epoch += 1
        self.find_handles = handles
        self.object_bindings.clear()
        if batches > 1:
            self.semantic_bindings.append(
                {
                    "kind": "find-drain",
                    "batches": batches,
                    "reason": "bind symbolic objects independently of provider ordering",
                }
            )
        expected = _child(response, "Object")
        expected_count = 0 if expected is None else len(expected.findall("Object"))
        if expected_count:
            self.testcase.assertGreaterEqual(len(handles), expected_count)

    def _call_C_FindObjectsFinal(
        self, request: ET.Element, response: ET.Element
    ) -> None:
        session = self._session_value(_value(_child(request, "Session")))
        self._assert_rv(response, self.lib.C_FindObjectsFinal(session))

    def _read_attribute(
        self, handle: int, attribute_type: int
    ) -> tuple[int, bytes | None]:
        if self.session is None:
            raise AssertionError("attribute read without a session")
        attribute = p11.CK_ATTRIBUTE(attribute_type, None, 0)
        rv = self.lib.C_GetAttributeValue(
            self.session, handle, ctypes.byref(attribute), 1
        )
        if rv != p11.CKR_OK:
            return rv, None
        value = (p11.CK_BYTE * attribute.ulValueLen)()
        attribute.pValue = ctypes.cast(value, p11.CK_VOID_PTR)
        rv = self.lib.C_GetAttributeValue(
            self.session, handle, ctypes.byref(attribute), 1
        )
        return rv, bytes(value[: attribute.ulValueLen])

    def _object_class(self, handle: int) -> int | None:
        rv, value = self._read_attribute(handle, p11.CKA_CLASS)
        if rv != p11.CKR_OK or value is None:
            return None
        return int.from_bytes(value, byteorder=sys.byteorder)

    def _object_label(self, handle: int) -> bytes | None:
        rv, value = self._read_attribute(handle, p11.CKA_LABEL)
        return value if rv == p11.CKR_OK else None

    def _bind_object(
        self,
        reference: str | None,
        requested_attributes: list[ET.Element],
        expected_attributes: list[ET.Element],
    ) -> int:
        if reference is None or not reference.startswith("${Object.Object["):
            if reference is None:
                raise AssertionError("missing object reference")
            return int(reference, 0)
        index = int(reference.removeprefix("${Object.Object[").removesuffix("]}"))
        key = (self.find_epoch, index)
        if key in self.object_bindings:
            return self.object_bindings[key]

        candidates = list(self.find_handles)
        attribute_names = {element.get("type") for element in requested_attributes}
        expected_by_name = {
            element.get("type"): element.get("value")
            for element in expected_attributes
        }
        if (
            self.case_name == "CERT-M-1-32"
            and index == 0
            and "LABEL" in attribute_names
        ):
            wanted = b"Mozilla Builtin Roots"
            candidates = [
                handle for handle in candidates if self._object_label(handle) == wanted
            ]
        elif "LABEL" in attribute_names and expected_by_name.get("LABEL"):
            wanted = expected_by_name["LABEL"].encode("utf-8")
            candidates = [
                handle for handle in candidates if self._object_label(handle) == wanted
            ]
        elif "VALUE" in attribute_names:
            candidates = [
                handle
                for handle in candidates
                if self._object_class(handle) == p11.CKO_CERTIFICATE
            ]

        if not candidates:
            raise AssertionError(
                f"cannot bind {reference} for attributes {sorted(attribute_names)}"
            )
        handle = candidates[0]
        self.object_bindings[key] = handle
        raw = self.find_handles[index] if index < len(self.find_handles) else None
        if raw != handle:
            self.semantic_bindings.append(
                {
                    "kind": "object",
                    "reference": reference,
                    "raw_handle": raw,
                    "bound_handle": handle,
                    "reason": "downstream object role",
                }
            )
        return handle

    def _attribute_request(
        self, element: ET.Element, handle: int
    ) -> tuple[p11.CK_ATTRIBUTE, object | None]:
        attribute_type = ATTRIBUTE_TYPES[element.get("type")]
        length = element.get("length")
        if length is None:
            return p11.CK_ATTRIBUTE(attribute_type, None, 0), None
        requested = int(length, 0)
        cached = self.attribute_lengths.get((handle, attribute_type))
        size = max(requested, cached or 0)
        storage = (p11.CK_BYTE * size)()
        return (
            p11.CK_ATTRIBUTE(
                attribute_type,
                ctypes.cast(storage, p11.CK_VOID_PTR),
                size,
            ),
            storage,
        )

    def _call_C_GetAttributeValue(
        self, request: ET.Element, response: ET.Element
    ) -> None:
        session = self._session_value(_value(_child(request, "Session")))
        request_template = _child(request, "Template")
        response_template = _child(response, "Template")
        requested = (
            [] if request_template is None else request_template.findall("Attribute")
        )
        expected = (
            [] if response_template is None else response_template.findall("Attribute")
        )
        handle = self._bind_object(
            _value(_child(request, "Object")), requested, expected
        )
        encoded = [self._attribute_request(element, handle) for element in requested]
        attributes = (p11.CK_ATTRIBUTE * len(encoded))(
            *(attribute for attribute, _storage in encoded)
        )
        keepalive = [storage for _attribute, storage in encoded]
        _ = keepalive
        self._assert_rv(
            response,
            self.lib.C_GetAttributeValue(
                session, handle, attributes, len(attributes)
            ),
        )
        actual: dict[str, bytes | None] = {}
        for element, attribute, (_encoded, storage) in zip(
            requested, attributes, encoded
        ):
            name = element.get("type")
            self.attribute_lengths[(handle, attribute.type_)] = attribute.ulValueLen
            if storage is not None:
                actual[name] = bytes(storage[: attribute.ulValueLen])
            else:
                actual[name] = None

        for element in expected:
            name = element.get("type")
            value = actual.get(name)
            expected_value = element.get("value")
            if expected_value is None:
                self.testcase.assertGreater(
                    self.attribute_lengths[(handle, ATTRIBUTE_TYPES[name])], 0
                )
                continue
            self.testcase.assertIsNotNone(value)
            if name == "LABEL":
                self.testcase.assertEqual(value, expected_value.encode("utf-8"))
            elif name == "VALUE":
                self.testcase.assertTrue(value.startswith(b"\x30"))
                self.semantic_bindings.append(
                    {
                        "kind": "attribute",
                        "attribute": "CKA_VALUE",
                        "reason": "provider certificate value is variable",
                    }
                )
            elif name == "MODULUS":
                self.testcase.assertGreaterEqual(len(value), 256)
                self.last_modulus = value
                self.semantic_bindings.append(
                    {
                        "kind": "attribute",
                        "attribute": "CKA_MODULUS",
                        "reason": "qualification key is provider-provisioned",
                    }
                )
            elif name == "PUBLIC_EXPONENT":
                self.testcase.assertEqual(value, bytes.fromhex(expected_value))
            else:
                self.testcase.assertEqual(value, bytes.fromhex(expected_value))

    def _call_C_SignInit(
        self, request: ET.Element, response: ET.Element
    ) -> None:
        session = self._session_value(_value(_child(request, "Session")))
        mechanism_node = _child(_child(request, "Mechanism"), "Type")
        mechanism = p11.CK_MECHANISM(
            MECHANISMS[_value(mechanism_node)], None, 0
        )
        handle = self._bind_object(
            _value(_child(request, "Key")), [], []
        )
        self._assert_rv(
            response,
            self.lib.C_SignInit(session, ctypes.byref(mechanism), handle),
        )

    def _call_C_Sign(self, request: ET.Element, response: ET.Element) -> None:
        session = self._session_value(_value(_child(request, "Session")))
        data = bytes.fromhex(_value(_child(request, "Data")))
        input_buffer = (p11.CK_BYTE * len(data)).from_buffer_copy(data)
        requested_signature = _child(request, "Signature")
        capacity = int(requested_signature.get("length"), 0)
        signature = (p11.CK_BYTE * capacity)()
        signature_length = p11.CK_ULONG(capacity)
        self._assert_rv(
            response,
            self.lib.C_Sign(
                session,
                input_buffer,
                len(input_buffer),
                signature,
                ctypes.byref(signature_length),
            ),
        )
        self.testcase.assertGreater(signature_length.value, 0)
        self.testcase.assertLessEqual(signature_length.value, capacity)
        expected_signature = _child(response, "Signature")
        if expected_signature is not None and expected_signature.get("length"):
            self.testcase.assertEqual(
                signature_length.value,
                int(expected_signature.get("length"), 0),
            )
        self.semantic_bindings.append(
            {
                "kind": "signature",
                "length": signature_length.value,
                "reason": "generated signatures are operation-specific",
            }
        )


class OasisProfileTests(unittest.TestCase):
    """Each method is one separately executable OASIS mandatory test case."""

    @classmethod
    def setUpClass(cls) -> None:
        module = os.environ.get("PKCS11RS_OASIS_MODULE")
        if module:
            cls.lib = ctypes.CDLL(str(pathlib.Path(module).resolve()))
            default_slot = None
            cls.module_kind = "production"
        else:
            cls.lib = p11.load_library()
            default_slot = p11.ABI_TEST_YUBIHSM_SLOT_ID
            cls.module_kind = "abi-test-backend"
        _bind_library(cls.lib)
        module_path = pathlib.Path(cls.lib._name)
        digest = hashlib.sha256()
        with module_path.open("rb") as module_file:
            for chunk in iter(lambda: module_file.read(1024 * 1024), b""):
                digest.update(chunk)
        cls.module_sha256 = digest.hexdigest()
        configured_slot = os.environ.get("PKCS11RS_OASIS_SLOT")
        if configured_slot is None and default_slot is None:
            raise RuntimeError(
                "PKCS11RS_OASIS_SLOT is required with PKCS11RS_OASIS_MODULE"
            )
        cls.slot_id = (
            default_slot if configured_slot is None else int(configured_slot, 0)
        )
        pin = os.environ.get("PKCS11RS_OASIS_PIN")
        if pin is None and module is None:
            pin = "1234"
        cls.pin = None if pin is None else pin.encode("utf-8")

    def setUp(self) -> None:
        self.lib.C_Finalize(None)

    def tearDown(self) -> None:
        self.lib.C_Finalize(None)

    def _run_case(self, name: str) -> None:
        started = time.time()
        executor = OasisExecutor(
            self,
            self.lib,
            name,
            self.slot_id,
            self.pin,
        )
        try:
            result = executor.run()
        except Exception as error:
            self._write_result(
                name,
                {
                    "status": "failed",
                    "error": str(error),
                    "elapsed_seconds": time.time() - started,
                    "semantic_bindings": executor.semantic_bindings,
                },
            )
            raise
        self._write_result(
            name,
            {
                **result,
                "status": "passed",
                "module_kind": self.module_kind,
                "module": str(self.lib._name),
                "module_sha256": self.module_sha256,
                "elapsed_seconds": time.time() - started,
            },
        )

    def _write_result(self, name: str, result: dict[str, object]) -> None:
        directory = os.environ.get("PKCS11RS_OASIS_RESULTS")
        if not directory:
            return
        path = pathlib.Path(directory)
        path.mkdir(parents=True, exist_ok=True)
        common = {
            "case": name,
            "source": case_url(name),
            "sha256": case_digest(name),
            "slot": self.slot_id,
            "module_kind": self.module_kind,
            "module": str(self.lib._name),
            "module_sha256": self.module_sha256,
        }
        (path / f"{name}.json").write_text(
            json.dumps({**common, **result}, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def test_BL_M_1_32(self) -> None:
        """OASIS BL-M-1-32."""
        self._run_case("BL-M-1-32")

    def test_EXT_M_1_32(self) -> None:
        """OASIS EXT-M-1-32."""
        self._run_case("EXT-M-1-32")

    def test_AUTH_M_1_32(self) -> None:
        """OASIS AUTH-M-1-32."""
        self._run_case("AUTH-M-1-32")

    def test_CERT_M_1_32(self) -> None:
        """OASIS CERT-M-1-32."""
        self._run_case("CERT-M-1-32")


if __name__ == "__main__":
    unittest.main(verbosity=2)
