"""Local HTTP fixtures; never access lab hardware or restart a service."""
import contextlib
import http.server
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import threading
import types
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "recovery_probe", Path(__file__).with_name("i2c-recovery-probe.py"))
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class RecoveryProbeTests(unittest.TestCase):
    def exercise(self, fail=True, reject_immediate=True, hsm_error=False):
        records = []
        lock = threading.Lock()
        fault = {"sent": False, "fresh_rejected": False}

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_POST(self):
                request = self.rfile.read(int(self.headers["Content-Length"]))
                serial = self.path.split("/")[3]
                fresh = request[3:].startswith(b"recovery-probe:")
                status = 200
                reply = b"\x81" + request[1:]
                with lock:
                    record = {"serial": serial, "request": request, "fresh": fresh}
                    records.append(record)
                    if fail and not fresh and serial == "24" and not fault["sent"]:
                        fault["sent"] = True
                        record["original_failure"] = True
                        status, reply = ((200, b"\x7f\x00\x01\x08") if hsm_error else
                                         (503, b'{"code":"device_transport_error"}'))
                    elif fresh and serial == "24" and reject_immediate and not fault["fresh_rejected"]:
                        fault["fresh_rejected"] = True
                        status, reply = 503, b'{"code":"device_transport_error"}'
                self.send_response(status)
                self.send_header("Content-Length", str(len(reply)))
                self.end_headers()
                self.wfile.write(reply)

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary) / "evidence"
                args = types.SimpleNamespace(
                    url=f"http://127.0.0.1:{server.server_port}", serials=["24", "25"],
                    output=str(directory), count=3, seed=91, max_payload=15,
                    timeout=2, retry_delays=[0], followups=1, systemd_service=None)
                with contextlib.redirect_stdout(io.StringIO()):
                    rc = probe.run(args)
                result = json.loads((directory / "result.json").read_text())
                self.assertFalse(list(directory.glob("*.tmp")))
                return rc, result, records
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_delayed_fresh_command_succeeds_without_replaying_original(self):
        rc, result, records = self.exercise()
        self.assertEqual(rc, 0)
        self.assertFalse(result["immediate_success"]["24"])
        self.assertTrue(result["available_after_probe"]["24"])
        failed = next(r["request"] for r in records if r.get("original_failure"))
        self.assertEqual(sum(r["serial"] == "24" and r["request"] == failed for r in records), 1)
        fresh = [r["request"] for r in records if r["fresh"]]
        self.assertEqual(len(fresh), len(set(fresh)), "every recovery command needs a distinct nonce")
        self.assertIsNone(result["connector_identity_unchanged"])
        self.assertEqual(result["intervention"], "none")

    def test_hsm_error_is_not_reported_as_transport_recovery(self):
        rc, result, _ = self.exercise(hsm_error=True, reject_immediate=False)
        self.assertEqual(rc, 0)
        self.assertEqual(result["failure_kind"], "hsm_error_reply")
        self.assertIn("does not prove an explicit recovery ioctl", result["limits"])

    def test_no_fault_is_not_counted_as_recovery_success(self):
        rc, result, records = self.exercise(fail=False)
        self.assertEqual(rc, 2)
        self.assertEqual(result["status"], "no_failure_observed")
        self.assertFalse(any(r["fresh"] for r in records))

    def test_failed_fresh_command_is_reported_when_no_more_probes_allowed(self):
        original = probe.fresh_echo
        try:
            probe.fresh_echo = lambda _endpoint, serial, label, _timeout: {
                "serial": serial, "label": label, "sent": 1, "passed": False}
            rc, result, _ = self.exercise()
        finally:
            probe.fresh_echo = original
        self.assertEqual(rc, 1)
        self.assertEqual(result["status"], "recovery_failed")

    def test_service_restart_cannot_be_reported_as_in_place_recovery(self):
        before = {"MainPID": "10", "InvocationID": "first", "NRestarts": "0"}
        after = {"MainPID": "11", "InvocationID": "second", "NRestarts": "1"}
        with mock.patch.object(probe, "service_identity", side_effect=[before, after]):
            rc, result, _ = self.exercise(reject_immediate=False)
        self.assertEqual(rc, 1)
        self.assertFalse(result["connector_identity_unchanged"])


if __name__ == "__main__":
    unittest.main()
