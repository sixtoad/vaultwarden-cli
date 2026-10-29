#!/usr/bin/env python3
"""Portable harness checks. These are never native qualification evidence."""
import importlib.util
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import signal
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("qualify", HERE / "qualify.py")
qualify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(qualify)


class HarnessTests(unittest.TestCase):
    def test_fixture_accepts_close_only_kqueue_and_closes_descriptors_on_failure(self):
        class CloseOnlyQueue:
            closed = False

            def control(self, *_args):
                return [SimpleNamespace(ident=123, fflags=1)]

            def close(self):
                self.closed = True

        for failure in [None, "registration", "queue-creation", "manifest"]:
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                run = qualify.Run(Path(temporary))
                run.binary = Path(temporary) / "probe"
                queue = CloseOnlyQueue()
                process = mock.Mock(pid=123, returncode=-signal.SIGABRT,
                                    stdin=io.BytesIO(), stdout=io.BytesIO())
                item = {"pid": 123, "pgid": 123, "kernel_exit_observed": False, "waited": False, "released": False}
                descriptors = os.pipe()
                with mock.patch.object(qualify.os, "pipe", return_value=descriptors), \
                        mock.patch.object(qualify.subprocess, "Popen", return_value=process), \
                        mock.patch.object(qualify.select, "kqueue", return_value=queue, create=True) as create_queue, \
                        mock.patch.object(qualify.select, "KQ_NOTE_EXIT", 1, create=True), \
                        mock.patch.object(run, "register", return_value=item) as register, \
                        mock.patch.object(run, "manifest") as manifest:
                    if failure == "registration":
                        register.side_effect = AttributeError("private-registration-detail")
                    elif failure == "queue-creation":
                        create_queue.side_effect = AttributeError("private-queue-detail")
                    elif failure == "manifest":
                        manifest.side_effect = OSError("private-report-detail")
                    if failure:
                        with self.assertRaises((AttributeError, OSError)):
                            run.fixture("crash")
                    else:
                        self.assertEqual(run.fixture("crash"), [item])
                        self.assertTrue(item["kernel_exit_observed"])
                        self.assertTrue(item["waited"])
                self.assertEqual(queue.closed, failure not in {"queue-creation", "manifest"})
                self.assertTrue(process.stdin.closed)
                self.assertTrue(process.stdout.closed)
                for descriptor in descriptors:
                    with self.assertRaises(OSError):
                        os.fstat(descriptor)

    def test_unexpected_native_exception_serializes_failed_result_and_retained_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "evidence"
            actual_stat = Path.stat
            def operator_stat(path, *args, **kwargs):
                fields = list(actual_stat(path, *args, **kwargs))
                fields[4] = 501  # Portable even when the test runner uses root.
                return os.stat_result(fields)

            def unexpected(run):
                run.active_case = "inspection"
                for _ in range(5):
                    run.observations.append({"case": "completed-primitive", "outcome": "pass",
                                             "production_gate_satisfied": False})
                raise AttributeError("private-native-exception-detail")

            with mock.patch.object(qualify.platform, "system", return_value="Darwin"), \
                    mock.patch.object(qualify.platform, "machine", return_value="arm64"), \
                    mock.patch.object(qualify.os, "geteuid", return_value=501), \
                    mock.patch.object(Path, "stat", new=operator_stat), \
                    mock.patch.object(Path, "is_file", return_value=True), \
                    mock.patch.object(qualify.resource, "setrlimit"), \
                    mock.patch.object(qualify.Run, "command", side_effect=[b"27.0.1", b"26A1", b"0"]), \
                    mock.patch.object(qualify.Run, "sdk_available", return_value=True), \
                    mock.patch.object(qualify.Run, "native", autospec=True, side_effect=unexpected) as native, \
                    mock.patch("builtins.print"):
                self.assertEqual(qualify.main(["--output", str(report), "--authorized-disposable-host"]), 1)
            native.assert_called_once()
            result = json.loads((report / "result.json").read_text())
            self.assertEqual(result["outcome"], "failed")
            self.assertEqual(result["reason"], "probe-failed-details-redacted")
            self.assertEqual(result["failures"][0], {"case": "inspection", "code": "probe-failed-details-redacted"})
            self.assertEqual(result["observations"], 6)
            self.assertFalse(result["production_enabled"])
            cleanup = json.loads((report / "cleanup.json").read_text())
            self.assertEqual(cleanup["outcome"], "uncertain-retained")
            self.assertTrue(cleanup["resources_retained"])
            self.assertFalse(cleanup["identity_reuse_permitted"])
            for name in ["result.json", "observations.json", "cleanup.json"]:
                self.assertNotIn("private-native-exception-detail", (report / name).read_text())

    def test_expired_budget_never_spawns(self):
        with tempfile.TemporaryDirectory() as temporary:
            run = qualify.Run(Path(temporary))
            run.deadline = 0
            with mock.patch.object(qualify.subprocess, "Popen") as spawn:
                with self.assertRaisesRegex(qualify.ProbeFailure, "run-deadline"):
                    run.command(["unused"])
            spawn.assert_not_called()

    def test_sdk_command_failure_does_not_swallow_interruptions_or_deadlines(self):
        with tempfile.TemporaryDirectory() as temporary:
            run = qualify.Run(Path(temporary))
            for code in ["controller-interrupted", "run-deadline", "tool-deadline"]:
                with self.subTest(code=code), mock.patch.object(run, "command", side_effect=qualify.ProbeFailure(code)):
                    with self.assertRaisesRegex(qualify.ProbeFailure, code):
                        run.sdk_available()
            with mock.patch.object(run, "command", side_effect=qualify.ProbeFailure("tool-failed")):
                self.assertFalse(run.sdk_available())
            self.assertEqual(run.active_case, "sdk-prerequisites")

    def test_inspection_requires_target_arguments_and_environment_positive_controls(self):
        with tempfile.TemporaryDirectory() as temporary:
            run = qualify.Run(Path(temporary))
            run.binary = Path(temporary) / "probe-original"
            complete = (f"123 {run.binary} inspection 4 vw49-argv-control "
                        "VW49_INSPECTION_CONTROL=vw49-visible-control").encode()
            run.check_inspection(complete, 123, b"private-marker")
            for view in [b"", b"123", complete.replace(b"123", b"124", 1),
                         complete.replace(str(run.binary).encode(), b"other-program"),
                         complete.replace(b"vw49-argv-control", b""),
                         complete.replace(b"VW49_INSPECTION_CONTROL=vw49-visible-control", b"")]:
                with self.subTest(view=view), self.assertRaisesRegex(qualify.ProbeFailure, "inspection-control-missing"):
                    run.check_inspection(view, 123, b"private-marker")
            with self.assertRaisesRegex(qualify.ProbeFailure, "synthetic-secret-visible"):
                run.check_inspection(complete + b" private-marker", 123, b"private-marker")

    def test_snapshot_hash_and_compiler_input_survive_checkout_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "checkout"
            source = root / "tests/fixtures/macos-boundary/probe.c"
            source.parent.mkdir(parents=True)
            source.write_bytes(b"original source")
            output = Path(temporary) / "evidence"
            output.mkdir()
            run = qualify.Run(output)
            with mock.patch.object(qualify, "ROOT", root), \
                    mock.patch.object(qualify, "SOURCES", ["tests/fixtures/macos-boundary/probe.c"]):
                hashes = run.snapshot_sources()
            source.write_bytes(b"replacement source")
            def compiler(argv, **_kwargs):
                self.assertIn(str(run.source_snapshot), argv)
                self.assertNotIn(str(source), argv)
                self.assertEqual(run.source_snapshot.read_bytes(), b"original source")
                raise qualify.ProbeFailure("tool-failed")
            with mock.patch.object(run, "command", side_effect=compiler):
                with self.assertRaises(qualify.ProbeFailure):
                    run.native()
            self.assertEqual(hashes["tests/fixtures/macos-boundary/probe.c"],
                             hashlib.sha256(b"original source").hexdigest())

    def test_save_syncs_parent_and_sync_failure_blocks_registration_release(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "record.json"
            with mock.patch.object(qualify, "sync_directory", wraps=qualify.sync_directory) as sync:
                qualify.save(path, {"record": 1})
            sync.assert_called_once_with(path.parent)
            run = qualify.Run(Path(temporary))
            read_fd, write_fd = os.pipe()
            record = {"pid": 123, "ppid": 122, "pgid": 123, "uid": os.geteuid(), "start_sec": 1, "start_usec": 2}
            os.write(write_fd, json.dumps(record).encode() + b"\n")
            os.close(write_fd)
            queue = mock.Mock()
            process = mock.Mock()
            run.binary = Path(temporary) / "probe"
            with os.fdopen(read_fd, "rb", buffering=0) as stream, \
                    mock.patch.object(run, "command", return_value=json.dumps(record).encode()), \
                    mock.patch.object(qualify.select, "kevent", create=True), \
                    mock.patch.multiple(qualify.select, KQ_FILTER_PROC=1, KQ_EV_ADD=2,
                                        KQ_EV_ONESHOT=4, KQ_NOTE_EXIT=8, create=True), \
                    mock.patch.object(qualify, "sync_directory", side_effect=OSError("sync-private-path")):
                with self.assertRaises(OSError):
                    run.register(process, queue, stream)
            process.stdin.write.assert_not_called()
            self.assertFalse(run.processes[-1]["released"])

    def test_cleanup_attempts_remaining_children_and_inventories_partial_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            run = qualify.Run(Path(temporary))
            partial = Path(temporary) / "probe-original"
            partial.write_bytes(b"private-artifact-content")
            first = mock.Mock(pid=101, returncode=None)
            first.poll.return_value = None
            first.kill.side_effect = OSError("private-path")
            first.wait.side_effect = subprocess.TimeoutExpired("private-command", 3)
            second = mock.Mock(pid=102, returncode=None)
            second.poll.return_value = None
            second.wait.side_effect = lambda **_kwargs: setattr(second, "returncode", -9)
            run.children = [first, second]
            run.cleanup()
            first.wait.assert_called_once()
            second.kill.assert_called_once()
            second.wait.assert_called_once()
            self.assertTrue(run.failed)
            resources = json.loads((Path(temporary) / "resources.json").read_text())
            self.assertIn("probe-original", [item["path"] for item in resources["files"]])
            self.assertTrue(partial.exists())
            self.assertNotIn("private-artifact-content", json.dumps(resources))

    def test_report_failures_do_not_skip_cleanup_or_publish_exception_text(self):
        actual_save = qualify.save
        for failed_name in ["environment.json", "matrix.json", "source-hashes.json"]:
            with self.subTest(name=failed_name), tempfile.TemporaryDirectory() as temporary:
                report = Path(temporary) / "evidence"
                def failing_save(path, value):
                    if path.name == failed_name:
                        raise OSError("private-report-path")
                    actual_save(path, value)
                with mock.patch.object(qualify, "save", side_effect=failing_save), \
                        mock.patch.object(qualify.resource, "setrlimit"), \
                        mock.patch.object(qualify.platform, "system", return_value="Linux"), \
                        mock.patch.object(qualify.Run, "cleanup", autospec=True, side_effect=qualify.Run.cleanup) as cleanup, \
                        mock.patch("builtins.print"):
                    self.assertEqual(qualify.main(["--output", str(report)]), 1)
                cleanup.assert_called_once()
                result = json.loads((report / "result.json").read_text())
                self.assertEqual(result["outcome"], "failed")
                self.assertNotIn("private-report-path", json.dumps(result))

    def test_source_read_failure_has_closed_redacted_result(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "evidence"
            with mock.patch.object(qualify, "SOURCES", ["nonexistent-private-source"]), \
                    mock.patch.object(qualify.resource, "setrlimit"), mock.patch("builtins.print"):
                self.assertEqual(qualify.main(["--output", str(report)]), 1)
            result = json.loads((report / "result.json").read_text())
            self.assertEqual(result["reason"], "source-read-failed")
            self.assertEqual(result["failures"][0]["case"], "source-snapshot")
            self.assertFalse(result["source_manifest_complete"])
            self.assertNotIn("nonexistent-private-source", json.dumps(result))

    def test_eligible_native_host_without_authorization_cannot_run_probes(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "evidence"
            with mock.patch.object(qualify.platform, "system", return_value="Darwin"), \
                    mock.patch.object(qualify.platform, "machine", return_value="arm64"), \
                    mock.patch.object(qualify.resource, "setrlimit"), \
                    mock.patch.object(qualify.Run, "command", side_effect=[b"13.0", b"22A1", b"0"]), \
                    mock.patch.object(qualify.Run, "native") as native, mock.patch("builtins.print"):
                self.assertEqual(qualify.main(["--output", str(report)]), 2)
            native.assert_not_called()
            result = json.loads((report / "result.json").read_text())
            self.assertEqual(result["reason"], "native-host-authorization-required")
            self.assertEqual(result["outcome"], "blocked")
            self.assertFalse(result["production_enabled"])
            self.assertEqual(result["observations"], 0)
            self.assertFalse((report / "probe-original").exists())
            self.assertFalse((report / "signatures.json").exists())
            self.assertFalse(json.loads((report / "environment.json").read_text())["native_host_authorized"])

    def test_cleanup_error_still_emits_failed_result(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "evidence"
            with mock.patch.object(qualify.Run, "cleanup", side_effect=OSError("private-path")), \
                    mock.patch.object(qualify.resource, "setrlimit"), \
                    mock.patch.object(qualify.platform, "system", return_value="Linux"), \
                    mock.patch("builtins.print"):
                self.assertEqual(qualify.main(["--output", str(report)]), 1)
            result = json.loads((report / "result.json").read_text())
            self.assertEqual(result["outcome"], "failed")
            self.assertEqual(result["reason"], "cleanup-failed-resources-retained")
            self.assertNotIn("private-path", (report / "cleanup.json").read_text())

    def test_unavailable_host_cannot_pass_or_launch_native_fixtures(self):
        if sys.platform == "darwin":
            self.skipTest("Linux unavailable-host assertion")
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "evidence"
            result = subprocess.run([sys.executable, str(HERE / "qualify.py"), "--output", str(report),
                                     "--authorized-disposable-host"], capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 2, result.stderr)
            state = json.loads((report / "result.json").read_text())
            self.assertEqual(state["outcome"], "blocked")
            self.assertFalse(state["production_enabled"])
            self.assertEqual(state["policy_contract"], "secret-access-only-2026-10-28")
            self.assertIsNone(state["mechanism_selected"])
            self.assertEqual(state["certified_versions"], [])
            self.assertTrue(state["source_manifest_complete"])
            self.assertTrue(all(case["outcome"] == "unavailable"
                                for case in json.loads((report / "matrix.json").read_text())))
            matrix = json.loads((report / "matrix.json").read_text())
            self.assertTrue(all(case["policy_contract"] == state["policy_contract"] for case in matrix))
            self.assertNotIn("containment", json.dumps(matrix))
            self.assertIn("consumer-execution-independence", {case["case"] for case in matrix})
            self.assertEqual(json.loads((report / "resources.json").read_text())["processes"], [])
            self.assertEqual(report.stat().st_mode & 0o777, 0o700)

    def test_existing_evidence_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "evidence"
            report.mkdir()
            sentinel = report / "retained"
            sentinel.write_text("existing evidence")
            result = subprocess.run([sys.executable, str(HERE / "qualify.py"), "--output", str(report)],
                                    capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(list(report.iterdir()), [sentinel])
            self.assertEqual(sentinel.read_text(), "existing evidence")

    def test_timed_out_direct_child_is_waited_and_output_is_not_published(self):
        with tempfile.TemporaryDirectory() as temporary:
            run = qualify.Run(Path(temporary))
            with self.assertRaises(qualify.ProbeFailure):
                run.command([sys.executable, "-c", "import time; print('synthetic-private-marker', flush=True); time.sleep(30)"],
                            timeout=0.1, capture=True)
            run.cleanup()
            self.assertTrue(all(child.returncode is not None for child in run.children))
            self.assertTrue(all(item["waited"] for item in run.processes))
            for path in Path(temporary).iterdir():
                self.assertNotIn(b"synthetic-private-marker", path.read_bytes())

    def test_missing_exit_evidence_retains_material_and_blocks_reuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            run = qualify.Run(Path(temporary))
            material = Path(temporary) / "synthetic-material.private"
            material.write_bytes(b"synthetic-private-marker")
            run.record_file(material, "synthetic-material")
            run.processes.append({"pid": 123456, "kind": "fixture", "kernel_exit_observed": False,
                                  "waited": False})
            run.cleanup()
            report = json.loads((Path(temporary) / "cleanup.json").read_text())
            self.assertEqual(report["outcome"], "uncertain-retained")
            self.assertEqual(report["unobserved_registered_pids"], [123456])
            self.assertFalse(report["identity_reuse_permitted"])
            self.assertFalse(report["material_deleted"])
            self.assertTrue(material.exists())


if __name__ == "__main__":
    unittest.main()
