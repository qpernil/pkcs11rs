"""Report and isolation regressions for the upstream runner; no hardware needed."""

import argparse
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import run_pkcs11test as runner


class UpstreamRunnerTests(unittest.TestCase):
    def xml(self, failure=""):
        return ('<testsuites><testsuite><testcase classname="Suite" name="Case" '
                f'status="run">{failure}</testcase></testsuite></testsuites>')

    def test_inventory_includes_parameterized_and_disabled_cases(self):
        output = ("Init.\n  Reserved\nCiphers/SecretKeyTest.\n"
                  "  Encrypt/3  # GetParam() = AES\n  DISABLED_BadLength\n")
        self.assertEqual(runner.parse_test_names(output), [
            "Init.Reserved", "Ciphers/SecretKeyTest.Encrypt/3",
            "Ciphers/SecretKeyTest.DISABLED_BadLength"])

    def test_legacy_skip_is_not_reported_as_a_pass(self):
        execution = {"returncode": 0, "output": (
            "Following tests were skipped because: unsupported mechanism\n"
            "  Suite.Case\n")}
        case = runner.parse_case("Suite.Case", self.xml(), execution)
        self.assertEqual(case["status"], "unsupported_or_skipped")
        self.assertIn("unsupported mechanism", case["internal_skips"])
        case = runner.parse_case("Suite.Case", self.xml('<failure>bad setup</failure>'), execution)
        self.assertEqual(case["status"], "failed")

    def test_crash_timeout_and_missing_report_are_distinct(self):
        for execution, expected in [({"returncode": -11}, "crashed"),
                                    ({"timeout": 60}, "timeout"),
                                    ({"returncode": 0}, "harness_error")]:
            with self.subTest(expected=expected):
                self.assertEqual(runner.parse_case("Suite.Case", None, execution)["status"], expected)

    def test_failed_exit_cannot_be_hidden_by_passing_xml(self):
        case = runner.parse_case("Suite.Case", self.xml(), {"returncode": 1})
        self.assertEqual(case["status"], "harness_error")
        with self.assertRaises(ValueError):
            runner.parse_case("Another.Case", self.xml(), {"returncode": 0})

    def test_fixture_failure_is_reported_and_cleaned_up(self):
        cleaned = []

        def setup(fixture):
            fixture.addCleanup(lambda: cleaned.append(True))
            raise OSError("fixture failed")

        with patch.object(runner.ClientTests, "setUp", setup):
            case = runner.run_one(argparse.Namespace(), Path("unused"), "Suite.Case")
        self.assertEqual(case["status"], "harness_error")
        self.assertEqual(cleaned, [True])

    def test_partial_report_never_claims_success(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "results.json"
            report = {"selected_count": 2, "cases": [{"status": "passed"}]}
            runner.write_report(path, report)
            self.assertFalse(json.loads(path.read_text())["successful"])
            report["cases"].append({"status": "crashed"})
            runner.write_report(path, report)
            saved = json.loads(path.read_text())
            self.assertTrue(saved["complete"])
            self.assertFalse(saved["successful"])
            self.assertEqual(saved["counts"], {"passed": 1, "crashed": 1})


if __name__ == "__main__":
    unittest.main()
