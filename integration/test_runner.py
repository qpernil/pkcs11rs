"""Safety regressions for the opt-in hardware fixture; no hardware required."""
import unittest
from unittest.mock import patch

import run_clients as runner


class FakeHardware:
    def __init__(self):
        self.objects = {("1006", "shared", "secrkey")}
        self.deleted = []
        self.fail_creation = False

    def command(self, *args, **kwargs):
        def value(option):
            return args[args.index(option) + 1] if option in args else None

        key_id, label, kind = value("--id"), value("--label"), value("--type")
        if "--keypairgen" in args:
            self.objects.update((key_id, label, k) for k in ("privkey", "pubkey"))
            if self.fail_creation:
                raise AssertionError("command timed out after creating the key")
            return "Created key pair"
        if "--delete-object" in args:
            # Cleanup must constrain all three fields, including ownership label.
            assert key_id and label and kind
            self.deleted.append((key_id, label, kind))
            self.objects.remove((key_id, label, kind))
            return ""
        assert "--list-objects" in args
        return "\n".join(
            f"Key Object;\n  uri: pkcs11:id={i};object={name};type={k}"
            for i, name, k in sorted(self.objects)
            if (key_id is None or key_id == i)
            and (label is None or label == name)
            and (kind is None or kind == k)
        )


class HardwareFixtureTests(unittest.TestCase):
    def setUp(self):
        self.hardware = FakeHardware()
        self.mock = patch.object(runner.ClientTests, "p11", side_effect=self.hardware.command)
        self.mock.start()
        self.addCleanup(self.mock.stop)
        self.case = runner.HardwareCryptoTests("test_hardware_opensc_login_and_random")
        self.case.ids = {}
        self.case.owned = []
        self.case.label_prefix = "client-fixture"
        self.case.before = self.case.inventory()

    def test_uncertain_creation_cleans_only_its_own_keys(self):
        self.hardware.fail_creation = True
        with self.assertRaisesRegex(AssertionError, "timed out"):
            self.case.p11("--keypairgen", "--id", "01", "--label", "key-01", login=True)
        self.case.cleanup_hardware()
        self.assertEqual(self.hardware.objects, {("1006", "shared", "secrkey")})
        self.assertEqual(len(self.hardware.deleted), 2)

    def test_concurrent_unowned_object_is_preserved_and_reported(self):
        self.case.p11("--keypairgen", "--id", "01", login=True)
        foreign = (self.case.ids["01"], "someone-else", "secrkey")
        self.hardware.objects.add(foreign)
        with self.assertRaisesRegex(AssertionError, "inventory differs"):
            self.case.cleanup_hardware()
        self.assertIn(foreign, self.hardware.objects)
        self.assertIn(("1006", "shared", "secrkey"), self.hardware.objects)

    def test_reusing_created_id_is_rejected(self):
        self.case.p11("--keypairgen", "--id", "01", login=True)
        with self.assertRaisesRegex(AssertionError, "refusing to reuse"):
            self.case.p11("--keypairgen", "--id", "01", login=True)
        self.case.cleanup_hardware()

    def test_token_and_credential_mutations_are_rejected(self):
        for operation in ("--init-token", "--init-pin", "--change-pin", "--unlock-pin",
                          "--delete-object", "--reset"):
            with self.subTest(operation=operation):
                with self.assertRaisesRegex(AssertionError, "unsafe hardware"):
                    self.case.p11(operation, login=True)
        self.assertEqual(self.hardware.objects, {("1006", "shared", "secrkey")})

    def test_inventory_without_parseable_uris_is_rejected(self):
        with patch.object(runner.ClientTests, "p11", return_value="Private Key Object;"):
            with self.assertRaisesRegex(AssertionError, "must report object URIs"):
                self.case.inventory()


if __name__ == "__main__":
    unittest.main()
