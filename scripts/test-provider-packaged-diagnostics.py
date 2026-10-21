#!/usr/bin/env python3
"""Portable tests of the closed, non-sensitive packaged probe diagnostics."""
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("packaged", Path(__file__).with_name("test-provider-packaged.py"))
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)
SECRET = b"password identity-reference PRIVATE KEY raw-request raw-response"


class DiagnosticsTests(unittest.TestCase):
    def test_success_requires_zero_exit_and_exact_single_marker(self):
        marker = b"COMPANION_PROVIDER_TLS_OK\n"
        for code, output, expected in [(0, marker, True), (1, marker, False),
                                       (0, marker * 2, False), (0, b"prefix" + marker, False),
                                       (0, b"", False)]:
            self.assertEqual(PROBE.app_diagnostics(code, output, b"")["passed"], expected)

    def test_only_closed_labels_survive_arbitrary_output(self):
        output = (SECRET + b"\nCOMPANION_PROVIDER_TLS_FAILED:configuration:none\n"
                  b"COMPANION_PROVIDER_TLS_NATIVE_REJECTED:session\n"
                  b"COMPANION_PROVIDER_TLS_FAILED:configuration:password\n"
                  b"COMPANION_PROVIDER_TLS_NATIVE_REJECTED:identity-reference\n"
                  b"COMPANION_PROVIDER_TLS_FAILED:configuration:none:raw-response\n")
        result = PROBE.app_diagnostics(1, output, SECRET)
        self.assertEqual(result["failures"], [{"phase": "configuration", "check": "none"}])
        self.assertEqual(result["native_rejections"], ["session"])
        for secret in SECRET.decode().split():
            self.assertNotIn(secret, json.dumps(result))

    def test_failure_marker_cannot_pass_with_success_marker(self):
        result = PROBE.app_diagnostics(0, b"COMPANION_PROVIDER_TLS_OK\n",
                                       b"COMPANION_PROVIDER_TLS_FAILED:finish:sessionUnlocked\n")
        self.assertFalse(result["passed"])

    def test_diagnostics_are_bounded(self):
        markers = (b"COMPANION_PROVIDER_TLS_FAILED:begin:none\n"
                   b"COMPANION_PROVIDER_TLS_NATIVE_REJECTED:review\n") * 10000
        result = PROBE.app_diagnostics(1, markers, markers)
        self.assertEqual(len(result["failures"]), 16)
        self.assertEqual(len(result["native_rejections"]), 16)

    def test_subprocess_failure_and_timeout_keep_only_sanitized_evidence(self):
        for error, code, timed_out in [
            (subprocess.CalledProcessError(1, [SECRET], output=SECRET,
                stderr=b"COMPANION_PROVIDER_TLS_FAILED:finish:sessionUnlocked\n"), 1, False),
            (subprocess.TimeoutExpired([SECRET], 45, output=SECRET, stderr=SECRET), None, True),
        ]:
            with patch.object(PROBE, "run", side_effect=error):
                result = PROBE.launch_app(Path("synthetic-app"), {})
            self.assertEqual(result["exit_code"], code)
            self.assertEqual(result["timed_out"], timed_out)
            self.assertFalse(result["passed"])
            self.assertNotIn(SECRET.decode(), json.dumps(result))

    def test_command_counts_are_closed_and_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "commands"
            self.assertEqual(sum(PROBE.command_counts(path).values()), 0)
            path.write_text('{"command":"session"}\n{"command":"decision"}\n{"command":"status"}\n')
            counts = PROBE.command_counts(path)
            self.assertEqual((counts["session"], counts["decision"], counts["status"]), (1, 1, 1))
            for content in [b'{"command":"password"}', SECRET, b"x" * 16385]:
                path.write_bytes(content)
                with self.assertRaises(RuntimeError) as raised:
                    PROBE.command_counts(path)
                self.assertNotIn("password", str(raised.exception))

    def test_dart_and_python_share_closed_vocabulary(self):
        source = (PROBE.ROOT / "companion/integration_test/provider_tls_smoke.dart").read_text()
        for name, expected in [("ProbePhase", PROBE.PHASES), ("ProbeCheck", PROBE.CHECKS)]:
            body = re.search(r"enum " + name + r"\s*\{([^}]+)\}", source, re.S).group(1)
            self.assertEqual({value.strip() for value in body.split(",") if value.strip()}, expected)


if __name__ == "__main__":
    unittest.main()
