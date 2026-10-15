#!/usr/bin/env python3
"""Portable regression tests for the native CI watchdog."""
import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
SCRIPT = Path(__file__).with_name("run-native-check.py")
SPEC = importlib.util.spec_from_file_location("native_check", SCRIPT)
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class NativeCheckTests(unittest.TestCase):
    def test_success_and_failure_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            for code in [0, 7]:
                self.assertEqual(CHECK.run(
                    [sys.executable, "-c", f"raise SystemExit({code})"],
                    Path(directory), 5,
                ), code)

    def test_hang_fails_even_when_diagnostics_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(CHECK, "diagnose", side_effect=OSError("synthetic")):
                with self.assertRaises(OSError):
                    CHECK.run([sys.executable, "-c", "import time; time.sleep(60)"],
                              Path(directory), 0.1)

    def test_timeout_collects_diagnostics_and_returns_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(CHECK, "diagnose") as diagnose:
                self.assertEqual(CHECK.run(
                    [sys.executable, "-c", "import time; time.sleep(60)"],
                    Path(directory), 0.1,
                ), 124)
                diagnose.assert_called_once()

    def test_diagnostics_exclude_unrelated_processes_and_arguments(self):
        table = "10 1 swift-test\n11 10 /usr/bin/xctest\n12 11 python3\n99 1 unrelated\n"
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(CHECK.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, table, "")) as run:
                CHECK.diagnose(10, Path(directory))
                self.assertNotIn("unrelated", (Path(directory) / "processes.txt").read_text())
                self.assertEqual(run.call_args_list[0].args[0], ["ps", "-axo", "pid=,ppid=,comm="])
                self.assertEqual(run.call_args_list[1].args[0][1], "11")

    def test_sampling_failure_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            results = [subprocess.CompletedProcess([], 0, "11 10 /usr/bin/xctest\n", ""),
                       subprocess.CompletedProcess([], 1, "", "synthetic sampling failure")]
            with patch.object(CHECK.subprocess, "run", side_effect=results):
                CHECK.diagnose(10, Path(directory))
            self.assertIn("synthetic sampling failure", (Path(directory) / "xctest-11.sample-error.txt").read_text())

    def test_exited_leader_cannot_leave_output_pipe_open(self):
        with tempfile.TemporaryDirectory() as directory:
            child = "import subprocess,sys; subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'])"
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--report", directory, "--",
                 sys.executable, "-c", child], capture_output=True, timeout=5,
            )
            self.assertEqual(result.returncode, 0)

    def test_sigterm_cleans_up_owned_child(self):
        with tempfile.TemporaryDirectory() as directory:
            ready = Path(directory) / "ready"
            child = "import os,pathlib,time; pathlib.Path(" + repr(str(ready)) + ").write_text(str(os.getpid())); time.sleep(60)"
            process = subprocess.Popen(
                [sys.executable, str(SCRIPT), "--report", directory, "--",
                 sys.executable, "-c", child], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            try:
                deadline = time.monotonic() + 5
                while not ready.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(ready.exists())
                child_pid = int(ready.read_text())
                process.send_signal(signal.SIGTERM)
                process.communicate(timeout=5)
                self.assertEqual(process.returncode, 143)
                with self.assertRaises(ProcessLookupError):
                    os.kill(child_pid, 0)
            finally:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)

    def test_cli_rejects_invalid_deadlines(self):
        with tempfile.TemporaryDirectory() as directory:
            for value in ["0", "-1", "nan", "inf", "601"]:
                result = subprocess.run(
                    [sys.executable, str(SCRIPT), "--report", directory,
                     "--timeout", value, "--", sys.executable, "-c", "pass"],
                    capture_output=True, timeout=5,
                )
                self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
