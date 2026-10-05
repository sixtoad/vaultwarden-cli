"""Isolated regressions for evidence-runner timeout cleanup and exit semantics."""
import ast
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

EVIDENCE = Path(__file__).resolve().parent


class RunnerRegressions(unittest.TestCase):
    def test_each_runner_kills_descendant_group_and_reaps_child_on_timeout(self):
        for name in ("semantic-runner.py", "verification-runner.py"):
            with self.subTest(runner=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                tree = ast.parse((EVIDENCE / name).read_text())
                function = next(node for node in tree.body
                                if isinstance(node, ast.FunctionDef) and node.name == "run_command")
                namespace = {"os": os, "signal": signal, "subprocess": subprocess}
                exec(compile(ast.Module(body=[function], type_ignores=[]), name, "exec"), namespace)
                heartbeat = root / "heartbeat"
                identities = root / "pids.json"
                descendant = (
                    "import pathlib,time; p=pathlib.Path(" + repr(str(heartbeat)) + "); "
                    "\nwhile True: p.write_text(str(time.monotonic_ns())); time.sleep(0.02)"
                )
                parent = (
                    "import json,os,pathlib,subprocess,sys,time; "
                    "child=subprocess.Popen([sys.executable,'-c'," + repr(descendant) + "]); "
                    "pathlib.Path(" + repr(str(identities)) + ").write_text(json.dumps([os.getpid(),child.pid])); "
                    "time.sleep(60)"
                )
                with (root / "output.log").open("w") as log:
                    code = namespace["run_command"]([sys.executable, "-c", parent], log,
                                                     os.environ.copy(), 2)
                self.assertEqual(code, 124)
                parent_pid, descendant_pid = json.loads(identities.read_text())
                # The immediate child must already be reaped on return.
                with self.assertRaises(ChildProcessError):
                    os.waitpid(parent_pid, os.WNOHANG)
                last = heartbeat.read_text()
                time.sleep(0.15)
                self.assertEqual(heartbeat.read_text(), last)
                # A reparented zombie is dead and cannot touch mutated source.
                stat = Path(f"/proc/{descendant_pid}/stat")
                if stat.exists():
                    self.assertEqual(stat.read_text().split(")", 1)[1].split()[0], "Z")

    def test_semantic_campaign_preserves_every_classification_and_fails_unresolved(self):
        cases = ((101, "test result: FAILED", "caught"),
                 (0, "test result: ok. 1 passed;", "survived"),
                 (124, "synthetic timeout classification", "timeout"),
                 (42, "synthetic build failure", "unviable-or-infrastructure"))
        for exit_code, output, classification in cases:
            with self.subTest(classification=classification), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / "src/access.rs"
                source.parent.mkdir()
                original = "if key.is_weak() { reject(); }\n"
                source.write_text(original)
                binary_dir = root / "bin"
                binary_dir.mkdir()
                cargo = binary_dir / "cargo"
                cargo.write_text(
                    "#!" + sys.executable + "\nimport pathlib,sys\n"
                    "mutated='if false' in pathlib.Path('src/access.rs').read_text()\n"
                    "print(" + repr(output) + " if mutated else 'test result: ok. 1 passed;')\n"
                    "sys.exit(" + str(exit_code) + " if mutated else 0)\n"
                )
                cargo.chmod(0o700)
                env = os.environ.copy()
                env["PATH"] = str(binary_dir) + os.pathsep + env["PATH"]
                env["STORY21_MUTANT_FILTER"] = "weak-key"
                env["STORY21_MUTATION_PHASE"] = "isolated"
                run = subprocess.run([sys.executable, str(EVIDENCE / "semantic-runner.py")],
                                     cwd=root, env=env, capture_output=True, text=True, timeout=10)
                self.assertEqual(run.returncode, 0 if classification == "caught" else 1,
                                 run.stdout + run.stderr)
                recorded = json.loads((root / "docs/implementation/2-1-evidence/isolated/results.json").read_text())
                self.assertEqual(len(recorded), 1)
                self.assertEqual(recorded[0]["classification"], classification)
                self.assertEqual(recorded[0]["mutant_exit"], exit_code)
                self.assertEqual(source.read_text(), original)


if __name__ == "__main__":
    unittest.main()
