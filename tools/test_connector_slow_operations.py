"""Ownership checks run without an SDK, network connection, or device."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location(
    "slow_operations", Path(__file__).with_name("connector-slow-operations.py"))
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


class CleanupOwnership(unittest.TestCase):
    def setUp(self):
        self.info = SimpleNamespace(id=123, object_type=3, label="unique-operation")
        self.obj = Mock()
        self.obj.get_info.return_value = self.info
        self.session = Mock()
        self.session.list_objects.return_value = [self.obj]

    def cleanup(self, baseline=None):
        return bench.cleanup_owned(self.session, baseline or {}, "unique-operation", 3)

    def test_never_deletes_an_object_present_before_the_run(self):
        with self.assertRaisesRegex(RuntimeError, "existed before"):
            self.cleanup({(3, 123): self.info})
        self.obj.delete.assert_not_called()

    def test_wrong_identity_is_preserved(self):
        self.info.label = "someone-elses-object"
        with self.assertRaisesRegex(RuntimeError, "unexpected object identity"):
            self.cleanup()
        self.obj.delete.assert_not_called()

    def test_duplicate_labels_are_not_deleted(self):
        other = Mock()
        other.get_info.return_value = SimpleNamespace(id=124, object_type=3, label="unique-operation")
        self.session.list_objects.return_value = [self.obj, other]
        with self.assertRaisesRegex(RuntimeError, "ambiguous"):
            self.cleanup()
        self.obj.delete.assert_not_called()
        other.delete.assert_not_called()

    def test_replaced_object_is_preserved(self):
        self.obj.get_info.side_effect = [self.info, SimpleNamespace(id=123, object_type=3, label="replacement")]
        with self.assertRaisesRegex(RuntimeError, "changed during inspection"):
            self.cleanup()
        self.obj.delete.assert_not_called()

    def test_owned_object_is_deleted_and_inventory_is_verified(self):
        with patch.object(bench, "snapshot", return_value={}) as snapshot:
            self.assertEqual(self.cleanup(), 1)
        self.obj.delete.assert_called_once_with()
        snapshot.assert_called_once_with(self.session)


if __name__ == "__main__":
    unittest.main()
