#!/usr/bin/env python3
"""Exercise the production module exclusively through OpenSC and OpenSSL CLIs."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from urllib.parse import quote


ROOT = Path(__file__).resolve().parents[1]
TOKEN = "client integration"


def clean_environment() -> dict[str, str]:
    # Never inherit configured hardware endpoints, discovery credentials, storage,
    # test backends, provider overrides, or verbose secret-bearing diagnostics.
    return {
        key: value for key, value in os.environ.items()
        if not key.startswith(("PKCS11", "OPENSSL", "OPENSC", "LIBP11"))
        and key != "RUST_LOG"
    }


def provider_path(openssl: str) -> Path | None:
    roots = [
        Path(openssl).resolve().parent.parent / "lib/ossl-modules",
        Path(openssl).parent.parent / "lib/ossl-modules",
        Path("/opt/homebrew/lib/ossl-modules"),
        Path("/usr/lib64/ossl-modules"),
        Path("/usr/lib/x86_64-linux-gnu/ossl-modules"),
    ]
    result = subprocess.run(
        [openssl, "version", "-m"], capture_output=True, text=True,
        env={**clean_environment(), "OPENSSL_CONF": os.devnull}, timeout=20,
        check=True,
    )
    match = re.search(r'MODULESDIR: "([^"]+)"', result.stdout)
    if match:
        roots.insert(0, Path(match.group(1)))
    for root in roots:
        for suffix in (".so", ".dylib", ".dll"):
            candidate = root / f"pkcs11prov{suffix}"
            if candidate.is_file():
                return candidate.resolve()
    return None


class ClientTests(unittest.TestCase):
    options: argparse.Namespace
    records: list[dict] = []

    def setUp(self) -> None:
        self.started = time.monotonic()
        self.commands: list[dict] = []
        self.secrets: list[str] = []
        temporary = tempfile.TemporaryDirectory(prefix="pkcs11rs-clients-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.token = self.options.hardware_token or TOKEN
        self.env = clean_environment()
        self.env.update({
            "PKCS11RS_HARDWARE_DISCOVERY": "0",
            "PKCS11RS_SOFTWARE_SLOTS": TOKEN,
            "PKCS11RS_TOKEN_STORAGE": str(self.directory / "tokens"),
            "LC_ALL": "C",
            "OPENSSL_CONF": str(self.directory / "default.cnf"),
        })
        (self.directory / "default.cnf").write_text("")
        for variable in ("CLIENT_USER_PIN", "CLIENT_SO_PIN", "CLIENT_NEW_PIN"):
            value = secrets.token_urlsafe(24)
            self.secrets.append(value)
            self.env[variable] = value
        self.env["PKCS11_PIN"] = self.env["CLIENT_USER_PIN"]
        self.env["CLIENT_MODULE"] = str(self.options.module)
        self.env["CLIENT_CONFIG"] = json.dumps({
            "version": 1,
            "hardware": {"discovery": False},
            "software": {"slots": [{"name": TOKEN}]},
            "storage": {"tokens": str(self.directory / "tokens")},
            "yubihsm": {"urls": []},
        })
        if self.options.hardware_token:
            self.env.pop("PKCS11RS_SOFTWARE_SLOTS")
            self.env.pop("PKCS11RS_TOKEN_STORAGE")
            self.env.pop("PKCS11_PIN")
            self.env["PKCS11RS_HARDWARE_DISCOVERY"] = "1"
            configuration = {
                "version": 1, "hardware": {"discovery": True},
                "software": {"slots": []}, "yubihsm": {"urls": []},
            }
            if self.options.discovery_pin_env:
                pin = os.environ[self.options.discovery_pin_env]
                self.secrets.append(pin)
                self.env["PKCS11RS_YUBIHSM_DISCOVERY"] = pin
                configuration["yubihsm"]["public_discovery"] = pin
            if self.options.hardware_login_pin_env:
                pin = os.environ[self.options.hardware_login_pin_env]
                self.secrets.extend(value for value in (pin, pin.split(":", 2)[-1]) if value)
                self.env["CLIENT_USER_PIN"] = pin
                self.env["PKCS11_PIN"] = pin
            self.env["CLIENT_CONFIG"] = json.dumps(configuration)
        if self.options.provider:
            self.env["CLIENT_PROVIDER"] = str(self.options.provider)
        (self.directory / "provider.cnf").write_text(
            "openssl_conf = openssl_init\n"
            "config_diagnostics = 1\n"
            "[openssl_init]\nproviders = providers\n"
            "[providers]\ndefault = default_provider\npkcs11 = token_provider\n"
            "[default_provider]\nactivate = 1\n"
            "[token_provider]\nidentity = pkcs11prov\n"
            "module = $ENV::CLIENT_PROVIDER\n"
            "pkcs11_module = $ENV::CLIENT_MODULE\n"
            "init_args = $ENV::CLIENT_CONFIG\nactivate = 1\n"
        )
        self.message = self.directory / "message.bin"
        self.message.write_bytes(b"pkcs11rs external client integration\x00\xff\n" * 2048)
        if self.options.hardware_token:
            return  # Hardware fixtures never initialize a token or change its PIN.
        self.p11("--init-token", "--label", TOKEN, "--so-pin", "env:CLIENT_SO_PIN")
        self.p11("--login", "--login-type", "so", "--so-pin", "env:CLIENT_SO_PIN",
                 "--init-pin", "--pin", "env:CLIENT_USER_PIN")

    def redact(self, text: str) -> str:
        for secret in self.secrets:
            text = text.replace(secret, "<redacted>")
        return text.replace(str(self.directory), "<fixture>")

    def run_command(self, args: list[str | Path], *, provider: bool = False,
                    fails: bool = False, overrides: dict | None = None) -> str:
        command = [str(arg) for arg in args]
        env = self.env.copy()
        if provider:
            env["OPENSSL_CONF"] = str(self.directory / "provider.cnf")
            # Supply these only through pReserved, so a dropped init_args value
            # cannot accidentally pass by falling back to the environment.
            env.pop("PKCS11RS_SOFTWARE_SLOTS", None)
            env.pop("PKCS11RS_TOKEN_STORAGE", None)
            env.pop("PKCS11RS_YUBIHSM_DISCOVERY", None)
        if overrides:
            env.update(overrides)
        started = time.monotonic()
        try:
            result = subprocess.run(
                command, cwd=self.directory, env=env, stdin=subprocess.DEVNULL,
                capture_output=True, timeout=self.options.timeout,
            )
        except subprocess.TimeoutExpired:
            self.commands.append({"argv": [self.redact(a) for a in command],
                                  "timeout": self.options.timeout})
            self.fail(f"Command timed out: {self.redact(' '.join(command))}")
        output = self.redact((result.stdout + result.stderr).decode("utf-8", "replace"))
        self.commands.append({
            "argv": [self.redact(a) for a in command],
            "returncode": result.returncode,
            "expected_failure": fails,
            "seconds": round(time.monotonic() - started, 3),
            "output": output,
        })
        detail = self.redact(" ".join(command)) + "\n" + output
        if fails:
            self.assertGreater(result.returncode, 0, detail)  # Signals are failures too.
        else:
            self.assertEqual(result.returncode, 0, detail)
        return output

    def p11(self, *args: str | Path, login: bool = False, **kwargs) -> str:
        command = [self.options.pkcs11_tool, "--module", self.options.module,
                   "--token-label", self.token]
        if login:
            command += ["--login", "--pin", "env:CLIENT_USER_PIN"]
        return self.run_command(command + list(args), **kwargs)

    def openssl(self, *args: str | Path, **kwargs) -> str:
        return self.run_command([self.options.openssl, *args], **kwargs)

    def keypair(self, kind: str = "RSA:2048", key_id: str = "01") -> Path:
        extra = ["--usage-decrypt"] if kind.startswith("RSA:") else []
        self.p11("--keypairgen", "--key-type", kind, "--id", key_id,
                 "--label", f"key-{key_id}", "--usage-sign", *extra, login=True)
        public = self.directory / f"public-{key_id}.der"
        self.p11("--read-object", "--type", "pubkey", "--id", key_id,
                 "--output-file", public, login=True)
        self.openssl("pkey", "-pubin", "-inform", "DER", "-in", public,
                     "-pubcheck", "-noout")
        return public

    def uri(self, key_id: str = "01", kind: str = "private") -> str:
        encoded_id = "".join(f"%{byte:02X}" for byte in bytes.fromhex(key_id))
        return f"pkcs11:token={quote(self.token, safe='')};id={encoded_id};type={kind}"

    def verify(self, public: Path, signature: Path, *, pss: bool = False) -> None:
        args = ["dgst", "-sha256", "-keyform", "DER", "-verify", public,
                "-signature", signature]
        if pss:
            args += ["-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:32"]
        self.openssl(*args, self.message)
        changed = self.directory / "changed.bin"
        changed.write_bytes(self.message.read_bytes() + b"tampered")
        output = self.openssl(*args, changed, fails=True)
        self.assertIn("Verification failure", output)


class OpenSCTests(ClientTests):
    def test_discovery_and_random(self) -> None:
        self.assertIn(TOKEN, self.p11("--list-slots"))
        mechanisms = self.p11("--list-mechanisms")
        for mechanism in ("RSA-PKCS", "ECDSA", "AES-CBC"):
            self.assertIn(mechanism, mechanisms)
        random = self.directory / "random.bin"
        self.p11("--generate-random", "64", "--output-file", random, login=True)
        self.assertEqual(len(random.read_bytes()), 64)

    def test_rsa_signatures(self) -> None:
        public = self.keypair()
        for mechanism, pss in (("SHA256-RSA-PKCS", False), ("SHA256-RSA-PKCS-PSS", True)):
            with self.subTest(mechanism=mechanism):
                signature = self.directory / "signature.bin"
                extra = ["--salt-len", "32"] if pss else []
                self.p11("--sign", "--id", "01", "--mechanism", mechanism,
                         "--input-file", self.message, "--output-file", signature,
                         *extra, login=True)
                self.verify(public, signature, pss=pss)

    def test_ecdsa_signature(self) -> None:
        public = self.keypair("EC:prime256v1")
        digest = self.directory / "digest.bin"
        digest.write_bytes(hashlib.sha256(self.message.read_bytes()).digest())
        signature = self.directory / "signature.der"
        self.p11("--sign", "--id", "01", "--mechanism", "ECDSA",
                 "--signature-format", "openssl", "--input-file", digest,
                 "--output-file", signature, login=True)
        self.verify(public, signature)

    def test_rsa_oaep_decrypt(self) -> None:
        public = self.keypair()
        plaintext = self.directory / "plaintext.bin"
        plaintext.write_bytes(b"external OAEP encryption\x00\xff")
        ciphertext = self.directory / "ciphertext.bin"
        self.openssl("pkeyutl", "-encrypt", "-pubin", "-keyform", "DER", "-inkey", public,
                     "-pkeyopt", "rsa_padding_mode:oaep", "-pkeyopt", "rsa_oaep_md:sha256",
                     "-pkeyopt", "rsa_mgf1_md:sha256", "-in", plaintext, "-out", ciphertext)
        recovered = self.directory / "recovered.bin"
        self.p11("--decrypt", "--id", "01", "--mechanism", "RSA-PKCS-OAEP",
                 "--hash-algorithm", "SHA256", "--mgf", "MGF1-SHA256",
                 "--input-file", ciphertext, "--output-file", recovered, login=True)
        self.assertEqual(recovered.read_bytes(), plaintext.read_bytes())

    def test_aes_import_encrypt_decrypt(self) -> None:
        # Public test vector, never a user credential or production key.
        key = bytes(range(16))
        key_file = self.directory / "aes.bin"
        key_file.write_bytes(key)
        self.p11("--write-object", key_file, "--type", "secrkey", "--key-type", "AES:16",
                 "--id", "02", "--private", "--sensitive", "--usage-decrypt", login=True)
        iv = "00" * 16
        for mechanism, cipher, sizes in (
            ("AES-CBC-PAD", "-aes-128-cbc", (0, 1, 15, 16, 17, 4095, 4096, 4097, 73728)),
            ("AES-CBC", "-aes-128-cbc", (16, 4096, 73728)),
            ("AES-ECB", "-aes-128-ecb", (16, 4096, 73728)),
        ):
            for size in sizes:
                with self.subTest(mechanism=mechanism, size=size):
                    plaintext = self.directory / "plaintext.bin"
                    plaintext.write_bytes(self.message.read_bytes()[:size])
                    expected = self.directory / "expected.bin"
                    openssl_extra = [] if mechanism == "AES-CBC-PAD" else ["-nopad"]
                    if mechanism != "AES-ECB":
                        openssl_extra += ["-iv", iv]
                    self.openssl("enc", cipher, "-K", key.hex(), *openssl_extra,
                                 "-in", plaintext, "-out", expected)
                    ciphertext = self.directory / "ciphertext.bin"
                    iv_args = [] if mechanism == "AES-ECB" else ["--iv", iv]
                    self.p11("--encrypt", "--id", "02", "--mechanism", mechanism, *iv_args,
                             "--input-file", plaintext, "--output-file", ciphertext, login=True)
                    self.assertEqual(ciphertext.read_bytes(), expected.read_bytes())
                    recovered = self.directory / "recovered.bin"
                    self.p11("--decrypt", "--id", "02", "--mechanism", mechanism, *iv_args,
                             "--input-file", ciphertext, "--output-file", recovered, login=True)
                    self.assertEqual(recovered.read_bytes(), plaintext.read_bytes())

    def test_login_persistence_and_deletion(self) -> None:
        self.keypair("EC:prime256v1")
        self.assertNotIn("key-01", self.p11("--list-objects", "--type", "privkey"))
        rejected = self.p11("--list-objects", login=True, fails=True,
                            overrides={"CLIENT_USER_PIN": self.env["CLIENT_NEW_PIN"]})
        self.assertIn("CKR_PIN_INCORRECT", rejected)
        self.assertIn("key-01", self.p11("--list-objects", "--type", "privkey", login=True))
        self.p11("--delete-object", "--type", "privkey", "--id", "01", login=True)
        self.assertNotIn("key-01", self.p11("--list-objects", "--type", "privkey", login=True))
        self.assertIn("key-01", self.p11("--list-objects", "--type", "pubkey", login=True))
        self.p11("--delete-object", "--type", "pubkey", "--id", "01", login=True)
        self.assertNotIn("key-01", self.p11("--list-objects", login=True))

    def test_pin_change_preserves_key(self) -> None:
        public = self.keypair()
        self.p11("--change-pin", "--new-pin", "env:CLIENT_NEW_PIN", login=True)
        rejected = self.p11("--list-objects", login=True, fails=True)
        self.assertIn("CKR_PIN_INCORRECT", rejected)
        self.env["CLIENT_USER_PIN"] = self.env["CLIENT_NEW_PIN"]
        signature = self.directory / "signature.bin"
        self.p11("--sign", "--id", "01", "--mechanism", "SHA256-RSA-PKCS",
                 "--input-file", self.message, "--output-file", signature, login=True)
        self.verify(public, signature)


class OpenSSLTests(ClientTests):
    def test_json_configuration_is_validated(self) -> None:
        self.keypair("EC:prime256v1")
        output = self.openssl("pkey", "-in", self.uri(), "-pubout", "-out", "public.pem",
                              provider=True, fails=True,
                              overrides={"CLIENT_CONFIG": '{"version":2}'})
        self.assertIn("Unable to load module", output)

    def test_provider_and_uri_selection(self) -> None:
        public = self.keypair("EC:prime256v1", "00a1ff")
        self.assertIn("libp11 PKCS#11 provider", self.openssl("list", "-providers", provider=True))
        exported = self.directory / "provider-public.der"
        self.openssl("pkey", "-in", self.uri("00a1ff"), "-pubout", "-outform", "DER",
                     "-out", exported, provider=True)
        self.assertEqual(exported.read_bytes(), public.read_bytes())
        self.openssl("pkey", "-in", self.uri("ff"), "-pubout", "-out", exported,
                     provider=True, fails=True)

    def test_provider_signatures(self) -> None:
        for key_id, kind, pss in (("01", "RSA:2048", False), ("02", "RSA:2048", True),
                                  ("03", "EC:prime256v1", False)):
            with self.subTest(kind=kind, pss=pss):
                public = self.keypair(kind, key_id)
                signature = self.directory / "signature.bin"
                extra = (["-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:32"]
                         if pss else [])
                self.openssl("dgst", "-sha256", "-sign", self.uri(key_id), *extra,
                             "-out", signature, self.message, provider=True)
                self.verify(public, signature, pss=pss)

    def test_provider_rsa_decrypt(self) -> None:
        public = self.keypair()
        plaintext = self.directory / "plaintext.bin"
        plaintext.write_bytes(b"OpenSSL provider decryption\x00\xff")
        for padding in ("pkcs1", "oaep"):
            with self.subTest(padding=padding):
                options = ["-pkeyopt", f"rsa_padding_mode:{padding}"]
                if padding == "oaep":
                    options += ["-pkeyopt", "rsa_oaep_md:sha256", "-pkeyopt", "rsa_mgf1_md:sha256"]
                ciphertext = self.directory / "ciphertext.bin"
                self.openssl("pkeyutl", "-encrypt", "-pubin", "-keyform", "DER", "-inkey", public,
                             *options, "-in", plaintext, "-out", ciphertext)
                recovered = self.directory / "recovered.bin"
                self.openssl("pkeyutl", "-decrypt", "-inkey", self.uri(), *options,
                             "-in", ciphertext, "-out", recovered, provider=True)
                self.assertEqual(recovered.read_bytes(), plaintext.read_bytes())

    def test_certificate_request(self) -> None:
        for key_id, kind in (("01", "RSA:2048"), ("02", "EC:prime256v1")):
            with self.subTest(kind=kind):
                public = self.keypair(kind, key_id)
                request = self.directory / "request.pem"
                self.openssl("req", "-new", "-sha256", "-key", self.uri(key_id),
                             "-subj", "/CN=pkcs11rs integration", "-out", request, provider=True)
                self.assertIn("verify OK", self.openssl("req", "-in", request, "-verify", "-noout"))
                pem = self.directory / "request-public.pem"
                der = self.directory / "request-public.der"
                self.openssl("req", "-in", request, "-pubkey", "-noout", "-out", pem)
                self.openssl("pkey", "-pubin", "-in", pem, "-outform", "DER", "-out", der)
                self.assertEqual(der.read_bytes(), public.read_bytes())


class HardwareTests(ClientTests):
    """Opt-in public discovery only; no login guesses, reset, or object mutations."""

    def test_hardware_opensc_discovery(self) -> None:
        self.assertIn(self.token, self.p11("--list-slots"))
        self.assertIn("RSA-PKCS", self.p11("--list-mechanisms"))
        objects = self.p11("--list-objects", "--type", "pubkey")
        if self.options.discovery_pin_env:
            self.assertIn("Public Key Object", objects)

    def test_hardware_provider_discovery(self) -> None:
        key_id = self.options.hardware_public_id
        public = self.directory / "opensc-public.der"
        self.p11("--read-object", "--type", "pubkey", "--id", key_id, "--output-file", public)
        exported = self.directory / "provider-public.der"
        self.openssl("pkey", "-pubin", "-in", self.uri(key_id, "public"), "-pubout",
                     "-outform", "DER", "-out", exported, provider=True)
        self.assertEqual(exported.read_bytes(), public.read_bytes())
        self.openssl("pkey", "-pubin", "-inform", "DER", "-in", exported, "-pubcheck", "-noout")


class HardwareCryptoTests(ClientTests):
    """Explicit HSM Auth login, temporary keys, and verified object cleanup."""

    def setUp(self) -> None:
        super().setUp()
        self.ids: dict[str, str] = {}
        self.owned: list[tuple[str, str, str]] = []
        self.label_prefix = f"client-{secrets.token_hex(8)}"
        self.before = self.inventory()
        self.addCleanup(self.cleanup_hardware)

    def inventory(self) -> set[str]:
        output = super().p11("--list-objects", login=True)
        uris = set(re.findall(r"^\s*uri:\s*(\S+)\s*$", output, re.MULTILINE))
        if re.search(r"\bObject\b", output):
            self.assertTrue(uris, "pkcs11-tool must report object URIs for inventory verification")
        return uris

    def hardware_id(self, logical: str) -> str:
        if logical not in self.ids:
            # Long PKCS #11 IDs use persisted metadata; the HSM allocates the
            # underlying physical ID, avoiding collisions with existing keys.
            actual = secrets.token_hex(16)
            output = super().p11("--list-objects", "--id", actual, login=True)
            self.assertNotRegex(output, r"\bObject\b", "temporary ID already exists")
            self.ids[logical] = actual
        return self.ids[logical]

    def p11(self, *args: str | Path, login: bool = False, **kwargs) -> str:
        args = list(args)
        forbidden = {"--init-token", "--init-pin", "--change-pin", "--unlock-pin",
                     "--delete-object", "--reset"}
        self.assertFalse(forbidden.intersection(args), "unsafe hardware test operation")
        logical = None
        if "--id" in args:
            index = args.index("--id") + 1
            logical = str(args[index])
            args[index] = self.hardware_id(logical)
        creating = "--keypairgen" in args or "--write-object" in args
        if creating:
            self.assertIsNotNone(logical, "hardware key creation needs an explicit ID")
            actual = self.ids[logical]
            self.assertFalse(any(key_id == actual for key_id, _, _ in self.owned),
                             "refusing to reuse a created hardware ID")
            label = f"{self.label_prefix}-{logical}"
            if "--label" in args:
                args[args.index("--label") + 1] = label
            else:
                args += ["--label", label]
            kinds = ("privkey", "pubkey") if "--keypairgen" in args else ("secrkey",)
            if "--write-object" in args:
                self.assertEqual(args[args.index("--type") + 1], "secrkey")
            # Register before dispatch so a timed-out command can still clean up
            # its own uniquely labelled additions. Never delete by ID alone.
            self.owned.extend((actual, label, kind) for kind in kinds)
        return super().p11(*args, login=login, **kwargs)

    def uri(self, key_id: str = "01", kind: str = "private") -> str:
        return super().uri(self.hardware_id(key_id), kind)

    def cleanup_hardware(self) -> None:
        failures = []
        for key_id, label, kind in self.owned:
            try:
                selector = ("--type", kind, "--id", key_id, "--label", label)
                output = super().p11("--list-objects", *selector, login=True)
                if re.search(r"\bObject\b", output):
                    super().p11("--delete-object", *selector, login=True)
                output = super().p11("--list-objects", *selector, login=True)
                self.assertNotRegex(output, r"\bObject\b", "temporary object remains")
            except (AssertionError, OSError) as error:
                failures.append(f"{kind} id={key_id} label={label}: {error}")
        try:
            self.assertEqual(self.inventory(), self.before,
                             "hardware object inventory differs after cleanup")
        except (AssertionError, OSError) as error:
            failures.append(str(error))
        self.assertFalse(failures, "Hardware cleanup failed:\n" + "\n".join(failures))

    def test_hardware_opensc_login_and_random(self) -> None:
        self.assertIn(self.token, self.p11("--list-slots"))
        random = self.directory / "random.bin"
        self.p11("--generate-random", "64", "--output-file", random, login=True)
        self.assertEqual(len(random.read_bytes()), 64)

    test_hardware_opensc_rsa_signatures = OpenSCTests.test_rsa_signatures
    test_hardware_opensc_ecdsa_signature = OpenSCTests.test_ecdsa_signature
    test_hardware_opensc_rsa_oaep_decrypt = OpenSCTests.test_rsa_oaep_decrypt
    test_hardware_opensc_aes_encrypt_decrypt = OpenSCTests.test_aes_import_encrypt_decrypt
    test_hardware_provider_uri_selection = OpenSSLTests.test_provider_and_uri_selection
    test_hardware_provider_signatures = OpenSSLTests.test_provider_signatures
    test_hardware_provider_rsa_decrypt = OpenSSLTests.test_provider_rsa_decrypt
    test_hardware_provider_certificate_request = OpenSSLTests.test_certificate_request


class RecordedResult(unittest.TextTestResult):
    def startTest(self, test):
        super().startTest(test)
        self.outcome = "passed"
        self.details = []

    def addFailure(self, test, err):
        self.outcome = "failed"
        self.details.append(test.redact(self._exc_info_to_string(err, test)))
        super().addFailure(test, err)

    def addError(self, test, err):
        self.outcome = "error"
        self.details.append(test.redact(self._exc_info_to_string(err, test)))
        super().addError(test, err)

    def addSubTest(self, test, subtest, err):
        if err is not None:
            self.outcome = "failed"
            self.details.append(test.redact(self._exc_info_to_string(err, test)))
        super().addSubTest(test, subtest, err)

    def stopTest(self, test):
        test.records.append({
            "case": test.id().split(".", 1)[-1], "status": self.outcome,
            "seconds": round(time.monotonic() - test.started, 3),
            "commands": test.commands,
            "details": self.details,
        })
        super().stopTest(test)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module", type=Path, help="Production module; otherwise build without hardware features")
    parser.add_argument("--provider", type=Path, help="libp11 pkcs11prov shared library (autodetected by default)")
    parser.add_argument("--client", choices=("all", "opensc", "openssl"), default="all")
    parser.add_argument("--pkcs11-tool", default="pkcs11-tool")
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--case", action="append", help="Run a named method, e.g. test_provider_signatures")
    parser.add_argument("--hardware-token", help="Select this exact hardware token; defaults to public discovery, requires --module")
    parser.add_argument("--hardware-public-id", help="Hex CKA_ID of an existing public key for OpenSSL discovery")
    parser.add_argument("--discovery-pin-env", help="Environment variable holding a confirmed YubiHSM public-discovery selector")
    parser.add_argument("--hardware-login-pin-env", help="Opt in to hardware crypto and temporary key creation using the HSM Auth login selector in this environment variable")
    parser.add_argument("--timeout", type=float, default=60, help="Per-command timeout in seconds")
    parser.add_argument("--results", type=Path, default=ROOT / "target/client-results.json")
    options = parser.parse_args()
    if options.hardware_token and not options.module:
        parser.error("--hardware-token requires an explicitly built native --module")
    if (options.hardware_token and options.client != "opensc"
            and not options.hardware_public_id and not options.hardware_login_pin_env):
        parser.error("Hardware OpenSSL discovery requires --hardware-public-id")
    if options.hardware_login_pin_env:
        if not options.hardware_token:
            parser.error("--hardware-login-pin-env requires --hardware-token")
        if options.discovery_pin_env or options.hardware_public_id:
            parser.error("Select authenticated hardware crypto or public discovery, not both")
        pin = os.environ.get(options.hardware_login_pin_env, "")
        if not re.fullmatch(r":[0-9a-fA-F]{4}[^:]+:.*", pin):
            parser.error("Hardware login requires an explicit :AAAA<label>[@source]:password HSM Auth selector")
    if options.hardware_public_id:
        if not options.hardware_token:
            parser.error("--hardware-public-id requires --hardware-token")
        if not re.fullmatch(r"(?:[0-9a-fA-F]{2})+", options.hardware_public_id):
            parser.error("--hardware-public-id must contain complete hexadecimal bytes")
    if options.discovery_pin_env:
        if not options.hardware_token:
            parser.error("--discovery-pin-env is only valid with --hardware-token")
        if not os.environ.get(options.discovery_pin_env):
            parser.error("The requested discovery credential environment variable is empty or unset")
    if not math.isfinite(options.timeout) or options.timeout <= 0:
        parser.error("--timeout must be positive")
    for name in ("pkcs11_tool", "openssl"):
        executable = shutil.which(getattr(options, name))
        if not executable:
            parser.error(f"Required executable is missing: {getattr(options, name)}")
        setattr(options, name, str(Path(executable).absolute()))
    if options.client != "opensc":
        options.provider = options.provider or provider_path(options.openssl)
        if not options.provider or not options.provider.is_file():
            parser.error("libp11 pkcs11prov provider is required; install it or pass --provider")
        options.provider = options.provider.resolve()
    else:
        options.provider = None
    if options.module is None:
        subprocess.run(["cargo", "build", "--locked", "-p", "pkcs11rs", "--no-default-features",
                        "--target-dir", str(ROOT / "target/client-tests")], cwd=ROOT, check=True)
        filename = {"Darwin": "libpkcs11rs.dylib", "Windows": "pkcs11rs.dll"}.get(
            platform.system(), "libpkcs11rs.so")
        options.module = ROOT / "target/client-tests/debug" / filename
    if not options.module.is_file():
        parser.error(f"Module does not exist: {options.module}")
    options.module = options.module.resolve()
    classes = {"opensc": [OpenSCTests], "openssl": [OpenSSLTests],
               "all": [OpenSCTests, OpenSSLTests]}[options.client]
    if options.hardware_token:
        classes = [HardwareCryptoTests if options.hardware_login_pin_env else HardwareTests]
    tests = [test for cls in classes for test in unittest.defaultTestLoader.loadTestsFromTestCase(cls)]
    if options.hardware_token and options.client != "all":
        selected = "opensc" if options.client == "opensc" else "provider"
        tests = [test for test in tests if selected in test._testMethodName]
    if options.case:
        unknown = set(options.case) - {test._testMethodName for test in tests}
        if unknown:
            parser.error(f"Unknown cases for selected client: {', '.join(sorted(unknown))}")
        tests = [test for test in tests if test._testMethodName in options.case]
    ClientTests.options = options
    ClientTests.records = []
    result = unittest.TextTestRunner(verbosity=2, resultclass=RecordedResult).run(unittest.TestSuite(tests))
    report = {
        "schema": "pkcs11rs.client-integration.v1",
        "client": options.client,
        "platform": platform.platform(),
        "module": str(options.module),
        "module_sha256": hashlib.sha256(options.module.read_bytes()).hexdigest(),
        "provider": str(options.provider) if options.provider else None,
        "provider_sha256": hashlib.sha256(options.provider.read_bytes()).hexdigest() if options.provider else None,
        "openssl": options.openssl,
        "pkcs11_tool": options.pkcs11_tool,
        "openssl_sha256": hashlib.sha256(Path(options.openssl).read_bytes()).hexdigest(),
        "pkcs11_tool_sha256": hashlib.sha256(Path(options.pkcs11_tool).read_bytes()).hexdigest(),
        "hardware_token": options.hardware_token,
        "hardware_mode": ("crypto" if options.hardware_login_pin_env else "discovery") if options.hardware_token else None,
        "cases": ClientTests.records,
        "successful": result.wasSuccessful(),
    }
    options.results.parent.mkdir(parents=True, exist_ok=True)
    options.results.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Results: {options.results}")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
