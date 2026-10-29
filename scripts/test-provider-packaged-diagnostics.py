#!/usr/bin/env python3
"""Portable tests of the closed, non-sensitive packaged probe diagnostics."""
import importlib.util
import ast
import json
import os
from pathlib import Path
import re
import shutil
import stat
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
    def test_controller_cases_extend_existing_matrix_and_use_production_controller(self):
        source = (PROBE.ROOT / "scripts/test-provider-packaged.py").read_text()
        tree = ast.parse(source)
        cases = next(ast.literal_eval(node.value) for node in ast.walk(tree)
                     if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "cases" for target in node.targets))
        self.assertEqual([case[0] for case in cases[:14]], ["approve", "deny", "wrong-password", "pin", "ca", "foreign-client", "unenrolled-client", "hostname", "expired", "redirect", "oversized", "schema", "lost-response-relaunch", "pending-relaunch"])
        self.assertEqual(len(cases), 20)
        self.assertEqual(cases[14][-1], ["session", "unlock", "session", "list", "review", "decision", "status", "status"])
        for case in cases[15:17]:
            self.assertEqual(case[-1], ["session", "review", "decision", "status"])
        self.assertEqual(cases[17][-1], ["session", "list", "session", "list", "history", "review"])
        for case in cases[18:]:
            self.assertEqual(case[-1], ["session", "list", "session", "list", "history"])
        dart = (PROBE.ROOT / "companion/integration_test/provider_tls_smoke.dart").read_text()
        for call in ["ProviderController(native)", "await controller.initialize()", "await controller.unlock(", "await controller.refresh()"]:
            self.assertIn(call, dart)
        self.assertIn("check=True, timeout=45", source)

    def test_progress_keeps_only_fixed_boundaries_on_failure(self):
        for diagnostics, prefix, phase, success in [
            (PROBE.app_diagnostics, b"COMPANION_PROVIDER_TLS", b"nativeSend", b"COMPANION_PROVIDER_TLS_OK\n"),
            (PROBE.provision_diagnostics, b"COMPANION_PROVIDER_PROVISION", b"savedIdentity", b"COMPANION_PROVIDER_PROVISION_OK\n"),
        ]:
            output = (SECRET + b"\n" + prefix + b"_PROGRESS:" + phase + b":enter\n"
                      + prefix + b"_PROGRESS:password:enter\n"
                      + prefix + b"_PROGRESS:" + phase + b":raw-response\n"
                      + prefix + b"_PROGRESS:" + phase + b":complete:identity-reference\n")
            result = diagnostics(None, b"", output, timed_out=True)
            self.assertFalse(result["passed"])
            self.assertEqual(result["progress"], [{"phase": phase.decode(), "event": "enter"}])
            for secret in SECRET.decode().split():
                self.assertNotIn(secret, json.dumps(result))
            self.assertNotIn("progress", diagnostics(0, success, output))

    def test_progress_keeps_latest_bounded_events_and_no_marker_is_explicit(self):
        old = b"COMPANION_PROVIDER_TLS_PROGRESS:startup:enter\n" * 10000
        last = b"COMPANION_PROVIDER_TLS_PROGRESS:nativeSend:enter\n"
        result = PROBE.app_diagnostics(None, b"", old + last, timed_out=True)
        self.assertEqual(len(result["progress"]), 32)
        self.assertEqual(result["progress"][-1], {"phase": "nativeSend", "event": "enter"})
        self.assertEqual(PROBE.app_diagnostics(None, b"", SECRET, timed_out=True)["progress"], [])

    def test_actual_timed_out_child_preserves_flushed_progress_without_raw_output(self):
        child = ("import sys,time; "
                 "sys.stderr.write('COMPANION_PROVIDER_TLS_PROGRESS:startup:enter\\n'); "
                 "sys.stderr.write('password identity-reference\\n'); "
                 "sys.stderr.flush(); time.sleep(30)")
        def bounded_run(argv, **options):
            return subprocess.run(argv, check=True, timeout=2, capture_output=True, **options)
        with patch.object(PROBE, "run", side_effect=bounded_run):
            result = PROBE.run_diagnosed([sys.executable, "-c", child], PROBE.app_diagnostics)
        self.assertTrue(result["timed_out"])
        self.assertFalse(result["passed"])
        self.assertEqual(result["progress"], [{"phase": "startup", "event": "enter"}])
        self.assertNotIn("password", json.dumps(result))

    def test_keychain_is_fresh_private_and_inside_app_container(self):
        with tempfile.TemporaryDirectory() as directory:
            container = Path(directory) / "Data"
            container.mkdir()
            existing = container / "existing-development-state"
            existing.write_text("untouched")
            first = PROBE.keychain_directory(container)
            second = PROBE.keychain_directory(container)
            self.assertEqual(first.parent, container)
            self.assertEqual(second.parent, container)
            self.assertNotEqual(first, second)
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(first.stat().st_mode), 0o700)
            self.assertEqual(list(first.iterdir()), [])
            # Mirror the exact directory-only cleanup used by the runner.
            shutil.rmtree(first)
            self.assertFalse(first.exists())
            self.assertTrue(second.is_dir())
            self.assertEqual(existing.read_text(), "untouched")

    def test_keychain_refuses_missing_or_redirected_container(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            missing = root / "missing"
            with self.assertRaisesRegex(RuntimeError, "Missing or redirected"):
                PROBE.keychain_directory(missing)
            # Windows CI need not grant symlink creation privileges for this
            # macOS-only refusal guard to be covered on every desktop runner.
            with patch.object(Path, "is_symlink", return_value=True):
                with self.assertRaisesRegex(RuntimeError, "Missing or redirected"):
                    PROBE.keychain_directory(root)
            self.assertEqual(list(root.iterdir()), [])

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

    def test_provision_diagnostics_accept_only_fixed_phases(self):
        marker = b"COMPANION_PROVIDER_PROVISION_OK\n"
        self.assertTrue(PROBE.provision_diagnostics(0, marker, SECRET)["passed"])
        self.assertFalse(PROBE.provision_diagnostics(1, marker, b"")["passed"])
        self.assertFalse(PROBE.provision_diagnostics(0, marker * 2, b"")["passed"])
        output = (b"COMPANION_PROVIDER_PROVISION_FAILED:savedIdentity\n"
                  b"COMPANION_PROVIDER_PROVISION_FAILED:password\n"
                  b"COMPANION_PROVIDER_PROVISION_FAILED:savedIdentity:identity-reference\n")
        result = PROBE.provision_diagnostics(1, output * 10000, SECRET)
        self.assertEqual(result["failures"], ["savedIdentity"] * 16)
        for secret in SECRET.decode().split():
            self.assertNotIn(secret, json.dumps(result))

    def test_provision_subprocess_errors_are_sanitized(self):
        for error in [subprocess.CalledProcessError(1, [SECRET], output=SECRET, stderr=SECRET),
                      subprocess.TimeoutExpired([SECRET], 45, output=SECRET, stderr=SECRET)]:
            with patch.object(PROBE, "run", side_effect=error):
                result = PROBE.run_diagnosed(["helper", SECRET], PROBE.provision_diagnostics)
            self.assertFalse(result["passed"])
            self.assertNotIn(SECRET.decode(), json.dumps(result))

    def test_swift_provision_phases_match_allowlist(self):
        source = (PROBE.ROOT / "companion/provider_native_tests/ProviderFixtureIdentity.swift").read_text()
        body = re.search(r"enum Phase: String\s*\{([^}]+)\}", source, re.S).group(1)
        values = re.findall(r"[A-Za-z]+", body)
        self.assertEqual(set(values) - {"case"}, PROBE.PROVISION_PHASES)

    def test_native_error_codes_are_closed_and_mapped_without_error_content(self):
        settings = (PROBE.ROOT / "companion/macos/Runner/ProviderSettings.swift").read_text()
        codes = set(re.findall(r'return "(provider_[a-z_]+)"', settings))
        self.assertEqual(codes, {"provider_configuration_unreadable", "provider_configuration_invalid", "provider_identity_unavailable"})
        dart = (PROBE.ROOT / "companion/integration_test/provider_tls_smoke.dart").read_text()
        self.assertEqual(set(re.findall(r"'(provider_[a-z_]+)' =>", dart)), codes)
        adapter = (PROBE.ROOT / "companion/macos/Runner/ProviderAdapter.swift").read_text()
        handler = adapter.split("catch let error as ProviderSettingsError {", 1)[1].split("} catch {", 1)[0]
        self.assertIn('code: error.code, message: "Provider setup, trust or transport unavailable.", details: nil', handler)


if __name__ == "__main__":
    unittest.main()
