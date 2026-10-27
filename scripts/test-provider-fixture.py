#!/usr/bin/env python3
"""Portable real-mTLS test of the packaged controller fixture's added commands."""
import http.client
import json
from pathlib import Path
import queue
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "companion/fixtures/provider_tls.py"


class ControllerFixtureTests(unittest.TestCase):
    def test_locked_unlock_list_and_committed_status_sequence(self):
        self.exercise_controller("controller")

    def test_pilot_requires_exact_unlock_password_without_logging_it(self):
        self.exercise_controller("pilot")

    def exercise_controller(self, mode):
        with tempfile.TemporaryDirectory(prefix="provider-controller-fixture-") as directory:
            root = Path(directory)
            subprocess.run([sys.executable, FIXTURE, "provision", root], check=True,
                           capture_output=True, timeout=30)
            server = subprocess.Popen([sys.executable, FIXTURE, "serve", root, "--mode", mode],
                                      stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            try:
                ready = queue.Queue(maxsize=1)
                reader = threading.Thread(target=lambda: ready.put(server.stdout.readline()), daemon=True)
                reader.start()
                port = int(ready.get(timeout=10))
                context = ssl.create_default_context(cafile=str(root / "ca.pem"))
                context.load_cert_chain(root / "client.pem", root / "client.key")

                def send(command, expected_status=200, **arguments):
                    connection = http.client.HTTPSConnection("127.0.0.1", port, context=context, timeout=5)
                    try:
                        connection.request("POST", "/v1/companion", json.dumps({"version": 1, "command": command, **arguments}),
                                           {"Content-Type": "application/json"})
                        response = connection.getresponse()
                        self.assertEqual(response.status, expected_status)
                        return json.loads(response.read())
                    finally:
                        connection.close()

                self.assertEqual(send("session")["state"], "locked")
                rejected = []
                if mode == "pilot":
                    for arguments in [{}, {"password": ""}, {"password": "synthetic-only"}, {"password": "wrong-value"}]:
                        self.assertEqual(send("unlock", expected_status=422, **arguments)["error"], "authentication_failed")
                        self.assertEqual(send("session")["state"], "locked")
                        rejected += ["unlock", "session"]
                password = "synthetic-pilot-unlock-only" if mode == "pilot" else "synthetic-only"
                self.assertEqual(send("unlock", password=password)["state"], "unlocked")
                self.assertEqual(send("session")["state"], "unlocked")
                request_id = "A" * 43
                self.assertEqual(send("list")["requests"], [request_id])
                self.assertEqual(send("review", request_id=request_id)["review"]["id"], request_id)
                self.assertEqual(send("decision", request_id=request_id, decision="approve", password="synthetic-only")["status"]["status"], "approved")
                self.assertEqual(send("status", request_id=request_id)["status"]["status"], "running")
                self.assertEqual(send("status", request_id=request_id)["status"], {"status": "completed", "exit_code": 0})
                commands = [json.loads(line)["command"] for line in (root / "requests.jsonl").read_text().splitlines()]
                self.assertEqual(commands, ["session", *rejected, "unlock", "session", "list", "review", "decision", "status", "status"])
                self.assertNotIn(password, (root / "requests.jsonl").read_text())
            finally:
                server.terminate()
                try:
                    server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=5)
                server.stdout.close()


if __name__ == "__main__":
    unittest.main()
