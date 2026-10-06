"""Device-selection guards, exercised without opening any device."""
import contextlib
import importlib.util
import io
from pathlib import Path
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch


spec = importlib.util.spec_from_file_location("rsa_matrix", Path(__file__).with_name("openpgp-rsa-matrix.py"))
matrix = importlib.util.module_from_spec(spec)
spec.loader.exec_module(matrix)


class StepQualification(unittest.TestCase):
    def test_sequence_halves_to_one_and_restores_known_size(self):
        self.assertEqual(matrix.HALVED_RSA_SIZES[0], 2048)
        self.assertEqual(matrix.HALVED_RSA_SIZES[-1], 2048)
        self.assertEqual([n - 2048 for n in matrix.HALVED_RSA_SIZES[1:-1]],
                         [256, 128, 64, 32, 16, 8, 4, 2, 1])

    def test_summary_requires_actual_crypto_success_per_slot(self):
        results = [{"slot": slot, "bits": 2048 + step, "status": status}
                   for slot in ("SIG", "DEC", "AUT")
                   for step, status in ((256, "passed"), (16, "passed"),
                                        (8, "rejected"), (1, "normalized"))]
        results.append({"slot": "AUT", "bits": 2052, "status": "passed"})
        self.assertEqual(matrix.step_summary(results), {"SIG": 16, "DEC": 16, "AUT": 4})
        self.assertEqual(matrix.step_summary([]), {"SIG": None, "DEC": None, "AUT": None})


class SelectionGuards(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.report = Path(self.directory.name) / "report.json"
        self.device = Mock()
        self.info = SimpleNamespace(serial=36707396, version=(5, 7, 4))
        self.discovery = Mock(return_value=[(self.device, self.info)])
        ykman_device = ModuleType("ykman.device")
        ykman_device.list_all_devices = self.discovery
        fido = ModuleType("yubikit.core.fido")
        fido.FidoConnection = object()
        pcsc = ModuleType("ykman.pcsc")
        self.ccid_discovery = Mock(return_value=[self.device])
        pcsc.list_devices = self.ccid_discovery
        self.modules = {"ykman": ModuleType("ykman"), "ykman.device": ykman_device,
                        "ykman.pcsc": pcsc,
                        "yubikit": ModuleType("yubikit"), "yubikit.core": ModuleType("yubikit.core"),
                        "yubikit.core.fido": fido}

    def invoke(self, serial=36707396, replace=True):
        args = ["matrix", "--serial", str(serial), "--report", str(self.report)]
        if replace:
            args.append("--replace-openpgp-keys")
        with patch.object(sys, "argv", args), patch.dict(sys.modules, self.modules), \
                patch.object(matrix, "qualify") as qualify, \
                contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            try:
                matrix.main()
            except SystemExit as error:
                self.assertEqual(error.code, 2)
                qualify.assert_not_called()
                self.device.open_connection.assert_not_called()
                return False
            qualify.assert_called_once()
            self.device.open_connection.assert_not_called()
            return True

    def test_protected_serial_rejected_before_discovery(self):
        self.assertFalse(self.invoke(serial=10462967))
        self.discovery.assert_not_called()

    def test_missing_overwrite_acknowledgement_rejected_before_discovery(self):
        self.assertFalse(self.invoke(replace=False))
        self.discovery.assert_not_called()

    def test_wrong_inserted_serial_rejected(self):
        self.info.serial = 12345678
        self.assertFalse(self.invoke())

    def test_nano_firmware_rejected(self):
        self.info.version = (5, 2, 4)
        self.assertFalse(self.invoke())

    def test_multiple_devices_rejected(self):
        self.discovery.return_value *= 2
        self.assertFalse(self.invoke())

    def test_no_device_rejected(self):
        self.discovery.return_value = []
        self.assertFalse(self.invoke())

    def test_existing_report_preserved(self):
        self.report.write_text("existing evidence")
        self.assertFalse(self.invoke())
        self.assertEqual(self.report.read_text(), "existing evidence")
        self.discovery.assert_not_called()

    def test_missing_ccid_reader_rejected(self):
        self.ccid_discovery.return_value = []
        self.assertFalse(self.invoke())

    def test_multiple_ccid_readers_rejected(self):
        self.ccid_discovery.return_value *= 2
        self.assertFalse(self.invoke())

    def test_exact_selected_device_reaches_matrix(self):
        self.assertTrue(self.invoke())

    def check_ccid_identity(self, serial, version, accepted):
        management = ModuleType("yubikit.management")
        identity = SimpleNamespace(serial=serial, version=version)
        management.ManagementSession = Mock()
        management.ManagementSession.return_value.read_device_info.return_value = identity
        openpgp = ModuleType("yubikit.openpgp")
        openpgp.OpenPgpSession = Mock()
        modules = dict(self.modules, **{"yubikit.management": management,
                                       "yubikit.openpgp": openpgp})
        connection = object()
        with patch.dict(sys.modules, modules):
            if accepted:
                matrix.openpgp_session(connection, 36707396)
                openpgp.OpenPgpSession.assert_called_once_with(connection)
            else:
                with self.assertRaises(RuntimeError):
                    matrix.openpgp_session(connection, 36707396)
                openpgp.OpenPgpSession.assert_not_called()

    def test_ccid_serial_mismatch_never_selects_openpgp(self):
        self.check_ccid_identity(10462967, (5, 7, 4), False)

    def test_ccid_nano_firmware_never_selects_openpgp(self):
        self.check_ccid_identity(36707396, (5, 2, 4), False)

    def test_matching_ccid_endpoint_selects_openpgp(self):
        self.check_ccid_identity(36707396, (5, 7, 4), True)


if __name__ == "__main__":
    unittest.main()
