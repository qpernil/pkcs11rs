#!/usr/bin/env python3
"""Destructive OpenPGP RSA qualification for an explicitly selected test YubiKey.

Requires the Python environment of yubikey-manager (ykman) and cryptography.
Never resets the applet or changes PINs. All three ordinary key slots are replaced.
"""

import argparse
from dataclasses import replace
from getpass import getpass
import hashlib
import json
from pathlib import Path
import subprocess
from urllib.parse import unquote_to_bytes


PROTECTED_SERIAL = 10462967
RSA_SIZES = tuple(range(1024, 4097, 256))
HALVED_RSA_SIZES = (2048, 2304) + tuple(2048 + (128 >> i) for i in range(8)) + (2048,)


def step_summary(results):
    """Report the smallest fully qualified increment, without inferring untested sizes."""
    return {slot: min((r["bits"] - 2048 for r in results
                      if r["slot"] == slot and r["status"] == "passed"
                      and r["bits"] > 2048), default=None)
            for slot in ("SIG", "DEC", "AUT")}


def openpgp_session(connection, serial):
    from yubikit.management import ManagementSession
    from yubikit.openpgp import OpenPgpSession
    identity = ManagementSession(connection).read_device_info()
    if identity.serial != serial or identity.version == (5, 2, 4):
        raise RuntimeError("CCID endpoint identity mismatch; OpenPGP not opened")
    return OpenPgpSession(connection)


def public_key_fingerprints(session):
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from yubikit.openpgp import KEY_REF
    return {
        ref.name: {"bits": public.key_size,
                   "sha256": hashlib.sha256(public.public_bytes(
                       Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).hexdigest()}
        for ref in (KEY_REF.SIG, KEY_REF.DEC, KEY_REF.AUT)
        for public in [session.get_public_key(ref)]
    }


def request_pin(prompt, pinentry):
    if not pinentry:
        return getpass(prompt + ": ")
    commands = f"SETTITLE OpenPGP RSA qualification\nSETDESC {prompt}\nSETPROMPT PIN:\nGETPIN\nBYE\n"
    response = subprocess.run([pinentry], input=commands, text=True,
                              capture_output=True, check=True).stdout
    for line in response.splitlines():
        if line.startswith("D "):
            return unquote_to_bytes(line[2:]).decode("utf-8")
    raise RuntimeError("PIN entry cancelled; no authentication retry")


def qualify(device, report, report_path, pinentry=None, factory_user_pin=False,
            factory_admin_pin=False, sizes=RSA_SIZES):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from yubikit.core.smartcard import ApduError, SmartCardConnection
    from yubikit.openpgp import (
        INS, KEY_REF, OpenPgpSession, RSA_IMPORT_FORMAT, RsaAttributes,
        RsaKeyTemplate,
    )

    def save():
        report_path.write_text(json.dumps(report, indent=2) + "\n")

    with device.open_connection(SmartCardConnection) as connection:
        session = openpgp_session(connection, report["serial"])
        advertised = session.get_algorithm_information()
        report["advertised"] = {
            ref.name: sorted({a.n_len for a in attrs if isinstance(a, RsaAttributes)})
            for ref, attrs in advertised.items()
        }
        templates = {}
        for ref in (KEY_REF.SIG, KEY_REF.DEC, KEY_REF.AUT):
            templates[ref] = next(
                a for a in advertised[ref]
                if isinstance(a, RsaAttributes)
                and a.import_format == RSA_IMPORT_FORMAT.STANDARD
            )
        # Keep only the card's authorization state, never PINs for later operations.
        session.verify_admin("12345678" if factory_admin_pin else request_pin("OpenPGP admin PIN", pinentry))
        message = b"OpenPGP RSA size qualification"
        last_keys = {}
        for bits in sizes:
            expected = {}
            host_key = None
            for ref in (KEY_REF.SIG, KEY_REF.DEC, KEY_REF.AUT):
                result = {"bits": bits, "slot": ref.name,
                          "advertised": bits in report["advertised"][ref.name]}
                report["results"].append(result)
                stage = "attributes"
                try:
                    attrs = replace(templates[ref], n_len=bits)
                    # Bypass SDK size allowlists: rejection must come from the card.
                    session.put_data(ref.algorithm_attributes_do, attrs)
                    readback = session.get_algorithm_attributes(ref)
                    result["attribute_bits"] = readback.n_len
                    if readback.n_len != bits:
                        result.update(status="normalized", stage="attributes")
                        print(json.dumps(result), flush=True)
                        save()
                        continue
                    if ref == KEY_REF.SIG:
                        stage = "generate"
                        session.protocol.send_apdu(0, INS.GENERATE_ASYM, 0x80, 0, ref.crt)
                    else:
                        stage = "import"
                        if host_key is None:
                            host_key = rsa.generate_private_key(65537, bits)
                        numbers = host_key.private_numbers()
                        prime_bytes = (bits + 15) // 16
                        template = RsaKeyTemplate(
                            ref.crt,
                            (65537).to_bytes((attrs.e_len + 7) // 8, "big"),
                            numbers.p.to_bytes(prime_bytes, "big"),
                            numbers.q.to_bytes(prime_bytes, "big"),
                        )
                        session.protocol.send_apdu(0, INS.PUT_DATA_ODD, 0x3F, 0xFF, bytes(template))
                        del template, numbers
                    public = session.get_public_key(ref)
                    result["public_key_bits"] = public.key_size
                    if public.key_size != bits:
                        result.update(status="normalized", stage="public-key-size")
                        print(json.dumps(result), flush=True)
                        save()
                        continue
                    expected[ref] = public.public_numbers()
                    stage = "operation"
                    session.verify_pin("123456" if factory_user_pin else request_pin(f"OpenPGP user PIN ({bits}, {ref.name})", pinentry),
                                       extended=ref != KEY_REF.SIG)
                    if ref == KEY_REF.DEC:
                        assert public.public_numbers() == host_key.public_key().public_numbers()
                        ciphertext = public.encrypt(message, padding.PKCS1v15())
                        assert session.decrypt(ciphertext) == message
                    else:
                        if ref == KEY_REF.AUT:
                            assert public.public_numbers() == host_key.public_key().public_numbers()
                        signature = (session.sign if ref == KEY_REF.SIG else session.authenticate)(
                            message, hashes.SHA256())
                        assert len(signature) == (bits + 7) // 8
                        public.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
                    result["status"] = "passed"
                except ApduError as error:
                    result.update(status="rejected", stage=stage, sw=f"{error.sw:04x}")
                    # Unexpected failures and rejection of advertised sizes are failures.
                    if (stage not in ("attributes", "generate", "import")
                            or result["advertised"]
                            or error.sw not in (0x6A80, 0x6A81, 0x6B00)):
                        save()
                        raise
                print(json.dumps(result), flush=True)
                save()
            del host_key
            last_keys.update(expected)
        # Reselect and check the final keys; physical power-cycle retention is
        # deliberately a separate qualification step.
        session = OpenPgpSession(connection)
        for ref, numbers in last_keys.items():
            assert session.get_public_key(ref).public_numbers() == numbers
        report["public_keys"] = public_key_fingerprints(session)
        if report.get("mode") == "halved-steps":
            report["smallest_qualified_increment"] = step_summary(report["results"])
        report["complete"] = True
        save()


def retention(device, report, report_path, capture, pinentry, factory_user_pin):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from yubikit.core.smartcard import ApduError, SmartCardConnection
    from yubikit.openpgp import KEY_REF
    with device.open_connection(SmartCardConnection) as connection:
        session = openpgp_session(connection, report["serial"])
        keys = public_key_fingerprints(session)
        if capture:
            if "public_keys" in report:
                raise RuntimeError("retention baseline already exists; it will not be replaced")
            for ref in (KEY_REF.SIG, KEY_REF.DEC, KEY_REF.AUT):
                passed = [r["bits"] for r in report["results"]
                          if r["slot"] == ref.name and r["status"] == "passed"]
                assert keys[ref.name]["bits"] == passed[-1]
            report["public_keys"] = keys
        else:
            assert keys == report["public_keys"], "public keys changed across power cycle"
            message = b"OpenPGP RSA power-cycle retention"
            slots = (KEY_REF.SIG, KEY_REF.DEC, KEY_REF.AUT)
            public = {ref: session.get_public_key(ref) for ref in slots}
            def operation(ref):
                if ref == KEY_REF.DEC:
                    return session.decrypt(public[ref].encrypt(message, padding.PKCS1v15()))
                return (session.sign if ref == KEY_REF.SIG else session.authenticate)(message, hashes.SHA256())
            # Check every operation before authorizing either of the shared PW1 roles.
            for ref in slots:
                try:
                    operation(ref)
                except ApduError as error:
                    assert error.sw == 0x6982
                else:
                    raise AssertionError("private operation authorized before fresh PIN verification")
            for ref in slots:
                session.verify_pin("123456" if factory_user_pin else request_pin(
                    f"OpenPGP user PIN (retention, {ref.name})", pinentry), extended=ref != KEY_REF.SIG)
                result = operation(ref)
                if ref == KEY_REF.DEC:
                    assert result == message
                else:
                    public[ref].verify(result, message, padding.PKCS1v15(), hashes.SHA256())
            report["retention_checked"] = True
        report_path.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"public_keys": keys, "retention_checked": report.get("retention_checked", False)}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True, type=int)
    parser.add_argument("--replace-openpgp-keys", action="store_true",
                        help="acknowledge irreversible replacement of SIG, DEC and AUT keys")
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--pinentry", help="PIN dialog executable, e.g. pinentry-mac")
    parser.add_argument("--factory-user-pin", action="store_true",
                        help="explicitly use factory user PIN 123456 for this test")
    parser.add_argument("--factory-admin-pin", action="store_true",
                        help="make one verification with factory admin PIN 12345678")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--halve-rsa-step", action="store_true",
                       help="qualify increments 256, 128, 64, 32, 16, 8, 4, 2 and 1 above 2048; finish with 2048-bit keys")
    modes.add_argument("--capture-retention-baseline", action="store_true")
    modes.add_argument("--check-retention", action="store_true",
                       help="after physical unplug/reinsert, verify recorded public keys and private operations")
    args = parser.parse_args()
    if args.serial == PROTECTED_SERIAL:
        parser.error("serial 10462967 is protected; no device connection attempted")
    check = args.capture_retention_baseline or args.check_retention
    if not check and not args.replace_openpgp_keys:
        parser.error("key replacement requires --replace-openpgp-keys")
    if not check and args.report.exists():
        parser.error("report path already exists; choose a new path")
    if check:
        report = json.loads(args.report.read_text())
        if report["serial"] != args.serial or not report["complete"]:
            parser.error("retention requires a completed matrix for the selected serial")
    from ykman.device import list_all_devices
    from yubikit.core.fido import FidoConnection
    # Read management information over FIDO only; never probe OpenPGP for discovery.
    devices = list_all_devices([FidoConnection])
    if len(devices) != 1:
        parser.error("connect only the selected test YubiKey; disconnect other YubiKeys")
    device, info = devices[0]
    if info.serial != args.serial:
        parser.error(f"inserted serial {info.serial} does not match requested serial")
    if info.serial == PROTECTED_SERIAL or info.version == (5, 2, 4):
        parser.error("protected key/firmware; OpenPGP will not be opened")
    from ykman.pcsc import list_devices
    ccid_devices = list_devices("Yubi")
    if len(ccid_devices) != 1:
        parser.error("expected exactly one YubiKey CCID reader")
    device = ccid_devices[0]
    if check:
        retention(device, report, args.report, args.capture_retention_baseline,
                  args.pinentry, args.factory_user_pin)
        return
    report = {"serial": info.serial, "firmware": str(info.version),
              "results": [], "complete": False,
              "mode": "halved-steps" if args.halve_rsa_step else "256-bit-matrix",
              "sizes": list(HALVED_RSA_SIZES if args.halve_rsa_step else RSA_SIZES)}
    print(f"Testing serial {info.serial}, firmware {info.version}; replacing SIG/DEC/AUT keys.")
    qualify(device, report, args.report, args.pinentry, args.factory_user_pin,
            args.factory_admin_pin, HALVED_RSA_SIZES if args.halve_rsa_step else RSA_SIZES)


if __name__ == "__main__":
    main()
