#!/usr/bin/env python3
"""Provision a selected lab Issuer SD and certify a smoke app's public host key.

Requires yubikey-manager and cryptography. Private CA/recovery state belongs in
a private directory outside the checkout; no host private key is imported.
"""
import argparse
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ObjectIdentifier


def save(path, data):
    """Exclusive creation prevents replacement of the saved recovery authority."""
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def certificate(public, issuer_key, subject, issuer, ca=False, oce=False):
    now = datetime.now(timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
               .public_key(public).serial_number(x509.random_serial_number())
               .not_valid_before(now - timedelta(days=1))
               .not_valid_after(now + timedelta(days=365))
               .add_extension(x509.BasicConstraints(ca, None), critical=True)
               .add_extension(x509.KeyUsage(not oce, False, False, False, True,
                                            ca, ca, False, False), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(public), False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                   issuer_key.public_key()), False))
    if oce:
        builder = builder.add_extension(x509.CertificatePolicies([
            x509.PolicyInformation(ObjectIdentifier("1.2.840.114283.100.0.10.2.1.0"), None)
        ]), critical=True)
    return builder.sign(issuer_key, hashes.SHA256())


def authority(directory):
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if directory.stat().st_mode & 0o077:
        raise ValueError("state directory must have mode 0700")
    key_path = directory / "ca-key.pem"
    if not key_path.exists():
        key = ec.generate_private_key(ec.SECP256R1())
        save(key_path, key.private_bytes(serialization.Encoding.PEM,
             serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    key = serialization.load_pem_private_key(key_path.read_bytes(), None)
    root_path = directory / "root.der"
    if not root_path.exists():
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pkcs11rs SCP11a smoke CA")])
        save(root_path, certificate(key.public_key(), key, name, name, ca=True)
             .public_bytes(serialization.Encoding.DER))
    root = x509.load_der_x509_certificate(root_path.read_bytes())
    if root.public_key().public_numbers() != key.public_key().public_numbers():
        raise ValueError("saved CA key and certificate disagree")
    return key, root


def provision(args, ca, root):
    from ykman._cli.__main__ import require_device
    from yubikit.core.smartcard import SmartCardConnection
    from yubikit.core.smartcard.scp import KeyRef, Scp03KeyParams, StaticKeys
    from yubikit.securitydomain import SecurityDomainSession

    # This serial is explicitly excluded from lab qualification.
    if args.serial == 10462967:
        raise ValueError("protected serial cannot be provisioned")
    # Use the same serial-scoped selection as `ykman --device SERIAL`.
    # All applet operations below act only on that selected Issuer SD.
    device, info = require_device([SmartCardConnection], args.serial)
    if info.serial != args.serial:
        raise ValueError("selected serial does not match the connected card")
    recovery_path = args.state_dir / f"{args.serial}-scp03.json"
    if not recovery_path.exists():
        with device.open_connection(SmartCardConnection) as connection:
            sd = SecurityDomainSession(connection)
            if set(sd.get_key_information()) != {KeyRef(1, 255), KeyRef(2, 255),
                                                 KeyRef(3, 255), KeyRef(0x13, 1)}:
                raise ValueError("bootstrap requires the expected factory inventory")
        recovery = {"version": 1, "scp03": {"key_version": 0x42,
            "enc_key": os.urandom(16).hex(), "mac_key": os.urandom(16).hex(),
            "dek_key": os.urandom(16).hex()}, "slots": {"serials": [str(args.serial)]},
            "ccid": {"applications": ["issuer-sd"], "secure_channel": "scp03"}}
        save(recovery_path, json.dumps(recovery, indent=2).encode())
    values = json.loads(recovery_path.read_bytes())["scp03"]
    keys = StaticKeys(*(bytes.fromhex(values[name]) for name in
                        ("enc_key", "mac_key", "dek_key")))
    admin = Scp03KeyParams(KeyRef(1, values["key_version"]), keys)
    with device.open_connection(SmartCardConnection) as connection:
        sd = SecurityDomainSession(connection)
        inventory = sd.get_key_information()
        if admin.ref not in inventory:
            if set(inventory) != {KeyRef(1, 255), KeyRef(2, 255), KeyRef(3, 255), KeyRef(0x13, 1)}:
                raise ValueError("saved administrator is absent from nonfactory inventory")
            sd.authenticate(Scp03KeyParams())
            sd.put_key(admin.ref, keys)
    # Independently authenticate saved recovery material before removing anything.
    with device.open_connection(SmartCardConnection) as connection:
        sd = SecurityDomainSession(connection)
        sd.authenticate(admin)
        sd.get_key_information()
        print(f"{args.serial}: saved SCP03 recovery credential independently verified")
        inventory = sd.get_key_information()
        allowed = {KeyRef(kid, 0x42) for kid in (1, 2, 3)} | {
            KeyRef(kid, 1) for kid in (0x10, 0x11, 0x13)} | {
            KeyRef(kid, 255) for kid in (1, 2, 3)}
        if set(inventory) - allowed:
            raise ValueError("unexpected key inventory; refusing modification")
        if KeyRef(0x13, 1) in inventory and args.replace_factory_scp11b:
            sd.delete_key(0x13, 1)
        card_ref = KeyRef(0x11, 1)
        if card_ref not in inventory:
            public = sd.generate_ec_key(card_ref)
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                 f"pkcs11rs SCP11a card {args.serial}")])
            leaf = certificate(public, ca, subject, root.subject)
            sd.store_certificate_bundle(card_ref, [root, leaf])
            sd.store_ca_issuer(card_ref, root.extensions.get_extension_for_class(
                x509.SubjectKeyIdentifier).value.digest)
        else:
            bundle = sd.get_certificate_bundle(card_ref)
            if len(bundle) != 2 or bundle[0].fingerprint(hashes.SHA256()) != root.fingerprint(hashes.SHA256()):
                raise ValueError("existing card key lacks the expected saved CA chain")
        ca_ref = KeyRef(0x10, 1)
        ski = root.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
        if ca_ref not in inventory:
            sd.put_key(ca_ref, ca.public_key())
            sd.store_ca_issuer(ca_ref, ski)
        elif sd.get_supported_ca_identifiers(kloc=True).get(ca_ref) != ski:
            raise ValueError("existing host CA identifier differs")
        print(f"{args.serial}: SCP11a card key 11/01, OCE CA 10/01; inventory",
              [(ref.kid, ref.kvn) for ref in sd.get_key_information()])
    with device.open_connection(SmartCardConnection) as connection:
        sd = SecurityDomainSession(connection)
        sd.authenticate(admin)
        sd.get_key_information()
    print("Administrative recovery verified after provisioning:", recovery_path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    card = commands.add_parser("provision")
    card.add_argument("--serial", type=int, required=True)
    card.add_argument("--replace-factory-scp11b", action="store_true")
    host = commands.add_parser("issue-host")
    host.add_argument("--public-key", type=Path, required=True, help="65-byte uncompressed P-256 SEC1 point")
    host.add_argument("--certificate", type=Path, required=True)
    args = parser.parse_args()
    ca, root = authority(args.state_dir)
    if args.command == "provision":
        if args.serial == 10462967:
            raise ValueError("protected serial cannot be provisioned")
        provision(args, ca, root)
    else:
        public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), args.public_key.read_bytes())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pkcs11rs smoke host")])
        save(args.certificate, certificate(public, ca, name, root.subject, oce=True)
             .public_bytes(serialization.Encoding.DER))
        print("Public OCE certificate issued:", args.certificate)


if __name__ == "__main__":
    main()
