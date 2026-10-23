#!/usr/bin/env python3
"""Portable checks for the isolated pilot-channel fixture's evidence boundaries."""
import base64
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("pilot", Path(__file__).with_name("test-pilot-packaged.py"))
PILOT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PILOT)


class PilotFixtureTests(unittest.TestCase):
    def test_commands_require_exactly_one_unlock_and_no_decisions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "requests.jsonl"
            for commands, valid in [(["unlock", "session", "list"], True),
                                    (["unlock", "unlock", "session", "list"], False),
                                    (["session", "unlock", "list"], False),
                                    (["unlock", "session", "list", "decision"], False), ([], False)]:
                path.write_text("".join(json.dumps({"command": command}) + "\n" for command in commands))
                if valid:
                    PILOT.verify_commands(path)
                else:
                    with self.assertRaises(RuntimeError):
                        PILOT.verify_commands(path)

    def test_persisted_configuration_requires_bundle_trust_and_no_recovery_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "configuration.json"
            bundle = {"endpoint": "https://127.0.0.1:1234/v1/companion", "leaf_sha256": "a" * 64, "ca_der": "AQID"}
            saved = {"endpoint": bundle["endpoint"], "leafSHA256": bundle["leaf_sha256"],
                     "trustedCA": bundle["ca_der"], "identityReference": base64.b64encode(b"synthetic-reference").decode()}
            path.write_text(json.dumps({"configuration": saved}))
            self.assertEqual(PILOT.verify_saved(path, bundle), path.read_bytes())
            for change in [{"endpoint": "https://other.example"}, {"leafSHA256": "b" * 64},
                           {"trustedCA": "BAUG"}, {"identityReference": ""}]:
                path.write_text(json.dumps({"configuration": dict(saved, **change)}))
                with self.assertRaises(RuntimeError):
                    PILOT.verify_saved(path, bundle)
            path.write_text(json.dumps({"configuration": saved, "pendingID": "A" * 43}))
            with self.assertRaises(RuntimeError):
                PILOT.verify_saved(path, bundle)

    def test_readiness_is_exact_bounded_and_never_reflects_child_output(self):
        for output, valid in [("COMPANION_PILOT_READY\\n", True),
                              ("prefixCOMPANION_PILOT_READY\\n", False),
                              ("private-key-password\\n", False)]:
            child = subprocess.Popen([sys.executable, "-c", f"import sys; sys.stdout.write('{output}'); sys.stdout.flush()"], stdout=subprocess.PIPE)
            try:
                if valid:
                    PILOT.wait_marker(child, b"COMPANION_PILOT_READY", seconds=2)
                else:
                    with self.assertRaisesRegex(RuntimeError, "^fixture readiness failed$"):
                        PILOT.wait_marker(child, b"COMPANION_PILOT_READY", seconds=2)
            finally:
                child.wait(timeout=5)
                child.stdout.close()

    def test_fixture_refuses_non_ci_execution_before_provisioning(self):
        result = subprocess.run([sys.executable, str(Path(__file__).with_name("test-pilot-packaged.py")),
                                 "nonexistent-app", "nonexistent-evidence"], env={}, capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"requires a disposable macOS CI runner", result.stderr)


if __name__ == "__main__":
    unittest.main()
