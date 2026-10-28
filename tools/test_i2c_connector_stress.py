"""Exercise real HTTP exchanges and persisted evidence without hardware."""
import http.server
import importlib.util
import socket
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

TOOL = Path(__file__).with_name("i2c-connector-stress.py")


class ConnectorStressTests(unittest.TestCase):
    def exercise(self, behavior, serials=("1",), count=5, timeout=2):
        received = []

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self):
                request = self.rfile.read(int(self.headers["Content-Length"]))
                received.append((self.path, request))
                reply = b"\x81" + request[1:]
                status = 200
                if behavior == "mismatch":
                    reply = b"\x80" + reply[1:]
                elif behavior == "http_error":
                    status, reply = 503, b'{"code":"device_transport_error"}'
                elif behavior == "timeout":
                    time.sleep(0.2)
                self.send_response(status)
                self.send_header("Content-Length", str(len(reply)))
                self.end_headers()
                try:
                    self.wfile.write(reply)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / "evidence"
                result = subprocess.run([
                    sys.executable, str(TOOL), "--url", f"http://127.0.0.1:{server.server_port}",
                    "--serials", *serials, "--count", str(count), "--max-payload", "16",
                    "--timeout", str(timeout), "--output", str(output),
                ], capture_output=True, text=True, timeout=10)
                summary = json.loads((output / "result.json").read_text())
                failure = json.loads((output / "first-error.json").read_text()) if (output / "first-error.json").exists() else None
                return result, summary, failure, list(received)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def scope_result(self, status, initial="Ready"):
        spec = importlib.util.spec_from_file_location("stress", TOOL)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        client, server = socket.socketpair()
        commands, errors = [], []

        def instrument():
            queries = 0
            try:
                with server, server.makefile("rb") as stream:
                    for line in stream:
                        command = line.decode().strip()
                        commands.append(command)
                        if command == "*OPC?":
                            server.sendall(b"1\n")
                        elif command == ":TRIG:STAT?":
                            queries += 1
                            answer = initial if queries == 1 else status
                            server.sendall((answer + "\n").encode())
            except Exception as error:
                errors.append(error)

        thread = threading.Thread(target=instrument)
        thread.start()
        try:
            with mock.patch.object(module.socket, "create_connection", return_value=client):
                result = module.freeze_scope("instrument")
        finally:
            client.close()
            thread.join(timeout=3)
        self.assertFalse(thread.is_alive())
        self.assertFalse(errors)
        return result, commands

    def test_scope_freeze_uses_documented_stop_and_checks_status(self):
        result, commands = self.scope_result("Stop")
        self.assertTrue(result["stopped"])
        self.assertNotIn("error", result)
        self.assertEqual(commands, [":TRIG:STAT?", ":TRIGger:STOP", ":TRIG:STAT?"])

    def test_scope_preserves_an_already_stopped_acquisition(self):
        result, commands = self.scope_result("Stop", initial="Stop")
        self.assertTrue(result["stopped"])
        self.assertTrue(result["preserved"])
        self.assertEqual(commands, [":TRIG:STAT?"])

    def test_scope_armed_reply_is_not_reported_as_a_frozen_capture(self):
        result, _ = self.scope_result("Arm")
        self.assertFalse(result["stopped"])
        self.assertIn("did not report Stop", result["error"])

    def test_two_serials_compare_complete_echo_frames(self):
        result, summary, failure, received = self.exercise("pass", serials=("1", "2"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(summary["passed"])
        self.assertIsNone(failure)
        self.assertEqual(len(received), 10)
        self.assertEqual({path for path, _ in received}, {"/v1/devices/1/commands", "/v1/devices/2/commands"})
        self.assertTrue(all(len(body) == 3 + int.from_bytes(body[1:3], "big") for _, body in received))

    def test_byte_mismatch_is_preserved_and_never_replayed(self):
        result, summary, failure, received = self.exercise("mismatch")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertFalse(summary["passed"])
        self.assertEqual(failure["error"], "byte mismatch")
        self.assertEqual(failure["first_differing_offset"], 0)
        self.assertEqual(len(received), 1)

    def test_http_error_is_distinguished_from_corrupted_echo(self):
        result, summary, failure, received = self.exercise("http_error")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(failure["status"], 503)
        self.assertEqual(failure["error"], "HTTP status 503")
        self.assertEqual(len(received), 1)

    def test_timeout_retains_attempt_without_replay(self):
        result, summary, failure, received = self.exercise("timeout", timeout=0.03)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("timed out", failure["error"])
        self.assertIn("request_sha256", failure)
        self.assertEqual(summary["results"][0]["completed"], 0)
        self.assertEqual(len(received), 1)


if __name__ == "__main__":
    unittest.main()
