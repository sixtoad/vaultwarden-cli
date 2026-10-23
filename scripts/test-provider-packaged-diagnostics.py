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
import time
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
        self.assertEqual(len(cases), 17)
        self.assertEqual(cases[14][-1], ["session", "unlock", "session", "list", "review", "decision", "status", "status"])
        for case in cases[15:]:
            self.assertEqual(case[-1], ["session", "review", "decision", "status"])
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

    def test_real_app_success_and_failure_do_not_sample(self):
        for code in (0, 7):
            with patch.object(PROBE, "sample_process") as sample:
                result = PROBE.run_app([sys.executable, "-c",
                    f"print('COMPANION_PROVIDER_TLS_OK'); raise SystemExit({code})"], dict(os.environ))
            self.assertEqual(result["exit_code"], code)
            self.assertEqual(result["passed"], code == 0)
            sample.assert_not_called()

    def test_real_timeout_samples_live_child_then_reaps_without_retry(self):
        children = []
        original = subprocess.Popen
        def start(*args, **kwargs):
            process = original(*args, **kwargs)
            children.append(process)
            return process
        def sample(pid):
            self.assertEqual(pid, children[0].pid)
            self.assertIsNone(children[0].poll())
            return {"status": "unavailable"}
        with patch.object(PROBE.subprocess, "Popen", side_effect=start), \
                patch.object(PROBE, "sample_process", side_effect=sample) as sampled:
            result = PROBE.run_app([sys.executable, "-c",
                "import time; print('COMPANION_PROVIDER_TLS_OK', flush=True); "
                "print('password PRIVATE KEY', flush=True); time.sleep(20)"], dict(os.environ), timeout=0.3)
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].returncode)
        sampled.assert_called_once()
        self.assertTrue(result["timed_out"])
        self.assertFalse(result["passed"])
        self.assertEqual(result["native_sample"], {"status": "unavailable"})
        self.assertNotIn("password", json.dumps(result))

    def test_sample_errors_are_closed_and_bounded(self):
        for error in (OSError(SECRET), subprocess.TimeoutExpired([SECRET], 5),
                      subprocess.CalledProcessError(1, [SECRET], output=SECRET)):
            with patch.object(PROBE.sys, "platform", "darwin"), \
                    patch.object(PROBE.subprocess, "run", side_effect=error) as run:
                self.assertEqual(PROBE.sample_process(123), {"status": "unavailable"})
                self.assertEqual(run.call_args.kwargs["timeout"], 5)
                self.assertEqual(run.call_args.args[0],
                    ["/usr/bin/sample", "123", "1", "10", "-file", "/dev/stdout"])

    @unittest.skipUnless(sys.platform == "darwin", "requires native macOS sampler")
    def test_native_sampler_recognizes_a_live_owned_process(self):
        with subprocess.Popen(["/bin/sleep", "10"]) as child:
            try:
                result = PROBE.sample_process(child.pid)
                self.assertEqual(result["status"], "captured")
                self.assertTrue(any(thread["main"] and thread["frames"] for thread in result["threads"]))
            finally:
                child.kill()
                child.wait(timeout=2)

    def test_inherited_pipe_does_not_remove_app_deadline(self):
        code = ("import subprocess,sys,time; "
                "subprocess.Popen([sys.executable,'-c','import time; time.sleep(2)']); "
                "print('COMPANION_PROVIDER_TLS_PROGRESS:startup:enter', flush=True); time.sleep(20)")
        start = time.monotonic()
        with patch.object(PROBE, "sample_process", return_value={"status": "unavailable"}), \
                patch.object(PROBE, "DRAIN_TIMEOUT", 0.1):
            result = PROBE.run_app([sys.executable, "-c", code], dict(os.environ), timeout=0.3)
        self.assertLess(time.monotonic() - start, 1.5)
        self.assertTrue(result["timed_out"])
        self.assertFalse(result["passed"])
        self.assertEqual(result["progress"], [{"phase": "startup", "event": "enter"}])

    def test_native_sample_retains_only_closed_frames_in_call_graph(self):
        raw = (SECRET + b"\nCall graph:\n"
               b"    99 Thread_123 DispatchQueue_1: com.apple.main-thread (serial)\n"
               b"      99 ProviderSettings.metadata() (in companion_slice) /password\n"
               b"        99 SecItemCopyMatching (in Security) + 12 [0xdeadbeef]\n"
               b"          99 private-secret-frame (in secret-library)\n"
               b"    99 Thread_234 secret-thread-name\n"
               b"      99 semaphore_wait_trap (in libsystem_kernel.dylib)\n"
               b"Binary Images:\nProviderAdapter /secret/path\n")
        result = PROBE.stack_diagnostics(raw)
        self.assertEqual(result, {"status": "captured", "threads": [
            {"main": True, "frames": [
                {"depth": 6, "samples": 99, "labels": ["ProviderSettings"]},
                {"depth": 8, "samples": 99, "labels": ["SecItemCopyMatching", "image:Security"]}]},
            {"main": False, "frames": [{"depth": 6, "samples": 99, "labels": ["semaphore_wait"]}]}]})
        for secret in [*SECRET.decode().split(), "123", "234", "deadbeef", "secret", "ProviderAdapter"]:
            self.assertNotIn(secret, json.dumps(result))
        self.assertEqual(PROBE.stack_diagnostics(SECRET)["status"], "unrecognized")
        self.assertEqual(PROBE.stack_diagnostics(b"x" * 1_048_577), {"status": "oversized"})
        many = b"Call graph:\n" + b"    1 Thread_123 secret\n      1 Dart_ (in FlutterMacOS)\n" * 1000
        self.assertEqual(len(PROBE.stack_diagnostics(many)["threads"]), 32)

    def test_sample_ignores_misleading_paths_and_keeps_branch_counts(self):
        raw = (b"Call graph:\n    85 Thread_1 DispatchQueue_1: com.apple.main-thread\n"
               b"      1 unknown (in private) /tmp/SecItemCopyMatching/ProviderSettings\n"
               b"      1 SecItemCopyMatching (in Security)\n"
               b"      84 FlutterThreadSynchronizer (in FlutterMacOS)\n"
               b"        84 semaphore_wait_trap (in libsystem_kernel.dylib)\n")
        frames = PROBE.stack_diagnostics(raw)["threads"][0]["frames"]
        self.assertEqual(len(frames), 3)
        self.assertEqual([frame["samples"] for frame in frames], [1, 84, 84])
        self.assertEqual([frame["depth"] for frame in frames], [6, 6, 8])
        self.assertNotIn("ProviderSettings", json.dumps(frames))

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
