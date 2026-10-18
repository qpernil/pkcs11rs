"""Build reuse and artifact isolation regressions; no Cargo or hardware needed."""
import os
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_libraries as libraries


class TestLibrarySelection(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for context in [patch.object(libraries, "ROOT", self.root),
                        patch.object(libraries, "_selected_libraries", {}),
                        patch.dict(os.environ, {
                            name: value for name, value in os.environ.items()
                            if name not in {*libraries.ENVIRONMENT.values(), "CARGO_TARGET_DIR"}
                        }, clear=True)]:
            context.start()
            self.addCleanup(context.stop)

    def fake_build(self, arguments, **kwargs):
        self.assertTrue(kwargs["check"])
        self.assertEqual(kwargs["cwd"], self.root)
        artifact = Path(arguments[arguments.index("--target-dir") + 1]) / "debug" / libraries.filename()
        artifact.parent.mkdir(parents=True, exist_ok=True)
        feature = arguments[arguments.index("--features") + 1] if "--features" in arguments else "software"
        artifact.write_bytes(feature.encode())

    def test_variants_share_compilation_but_never_overwrite_loaded_artifacts(self):
        with patch.object(libraries, "run_cargo", side_effect=self.fake_build) as cargo:
            first = libraries.build_library("abi")
            second = libraries.build_library("embedded")
            software = libraries.build_library("software")
        self.assertEqual(first.read_bytes(), b"abi-tests")
        self.assertEqual(second.read_bytes(), b"embedded-virtual-yubikey")
        self.assertEqual(software.read_bytes(), b"software")
        self.assertEqual(len({first, second, software}), 3)
        targets = {call.args[0][-1] for call in cargo.call_args_list}
        self.assertEqual(targets, {str((self.root / "target").resolve())})
        for call in cargo.call_args_list:
            self.assertIn("--locked", call.args[0])
        self.assertIn("--no-default-features", cargo.call_args_list[1].args[0])
        self.assertIn("--no-default-features", cargo.call_args_list[2].args[0])

    def test_explicit_prebuilt_library_never_invokes_cargo(self):
        path = self.root / libraries.filename()
        path.write_bytes(b"prebuilt")
        os.environ[libraries.ENVIRONMENT["abi"]] = str(path)
        with patch.object(libraries, "run_cargo") as cargo:
            self.assertEqual(libraries.ensure_library("abi"), path.resolve())
            cargo.assert_not_called()
        # Tests may clear PKCS11RS_* settings without changing the loaded DLL.
        for name in libraries.ENVIRONMENT.values():
            os.environ.pop(name, None)
        self.assertEqual(libraries.selected_library("abi"), path.resolve())

    def test_missing_or_invalid_explicit_library_fails_without_rebuilding(self):
        with patch.object(libraries, "run_cargo") as cargo:
            os.environ[libraries.ENVIRONMENT["abi"]] = str(self.root / "missing")
            with self.assertRaises(FileNotFoundError):
                libraries.ensure_library("abi")
            os.environ[libraries.ENVIRONMENT["abi"]] = str(self.root)
            with self.assertRaises(ValueError):
                libraries.ensure_library("abi")
            cargo.assert_not_called()

    def test_automatic_build_is_selected_once_and_remains_stable(self):
        with patch.object(libraries, "run_cargo", side_effect=self.fake_build) as cargo:
            first = libraries.ensure_library("embedded")
            for name in libraries.ENVIRONMENT.values():
                os.environ.pop(name, None)
            self.assertEqual(libraries.ensure_library("embedded"), first)
            self.assertEqual(cargo.call_count, 1)

    def test_unchanged_snapshot_is_not_rewritten(self):
        with patch.object(libraries, "run_cargo", side_effect=self.fake_build):
            first = libraries.build_library("abi")
            with patch.object(libraries.shutil, "copy2") as copy:
                self.assertEqual(libraries.build_library("abi"), first)
                copy.assert_not_called()

    def test_platform_detection_can_run_its_own_subprocess(self):
        # Windows platform.system() may run `ver`; the Cargo mock must not
        # intercept those standard-library subprocess calls.
        def detect():
            return subprocess.check_output(
                [sys.executable, "-c", "print('Windows')"], text=True).strip()
        with patch.object(libraries.platform, "system", side_effect=detect):
            with patch.object(libraries, "run_cargo", side_effect=self.fake_build):
                path = libraries.build_library("abi")
        self.assertEqual(path.name, "pkcs11rs.dll")

    def test_relative_cargo_target_directory_uses_repository_root(self):
        os.environ["CARGO_TARGET_DIR"] = "shared-artifacts"
        with patch.object(libraries, "run_cargo", side_effect=self.fake_build) as cargo:
            libraries.build_library("abi")
        self.assertEqual(cargo.call_args.args[0][-1], str((self.root / "shared-artifacts").resolve()))


if __name__ == "__main__":
    unittest.main()
