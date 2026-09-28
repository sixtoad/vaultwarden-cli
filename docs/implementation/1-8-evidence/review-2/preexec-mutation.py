#!/usr/bin/env python3
"""Replay the focused pre-exec SIGKILL regression and restore its source."""

import difflib
import hashlib
import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[4]
EVIDENCE = Path(__file__).resolve().parent
SOURCE = ROOT / "src/adapters/supervisor/bridge.rs"
TEST = (
    "adapters::supervisor::bridge::tests::"
    "pre_exec_sigkill_with_empty_error_pipe_reports_failure_and_confirmed_cleanup"
)
ORIGINAL = "    let confirmed = trace_exec(child) && confirm_exec(read.as_raw_fd());"
MUTATED = (
    "    let _ignored_trace_result = trace_exec(child);\n"
    "    let confirmed = confirm_exec(read.as_raw_fd());"
)


def run(label, test, exact=False):
    command = [
        "scripts/with-secure-test-tmpdir.sh", "cargo", "test", "--lib", test,
        "--", "--test-threads=1",
    ]
    if exact:
        command.append("--exact")
    with (EVIDENCE / f"preexec-{label}.log").open("w") as log:
        log.write("command: " + " ".join(command) + "\n")
        log.flush()
        result = subprocess.run(
            command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, timeout=180,
            check=False,
        )
        log.write(f"\nexit_code: {result.returncode}\n")
    return result.returncode


def main():
    original = SOURCE.read_bytes()
    text = original.decode()
    assert text.count(ORIGINAL) == 1
    mutated = text.replace(ORIGINAL, MUTATED)
    summary = {
        "test": TEST,
        "mutation": "Run trace_exec but discard its result; authorize EXEC from pipe EOF alone",
        "source_sha256_before": hashlib.sha256(original).hexdigest(),
    }
    (EVIDENCE / "preexec-ignore-trace.diff").write_text("".join(difflib.unified_diff(
        text.splitlines(keepends=True), mutated.splitlines(keepends=True),
        fromfile="a/src/adapters/supervisor/bridge.rs",
        tofile="b/src/adapters/supervisor/bridge.rs",
    )))
    summary["baseline_exit"] = run("baseline", "adapters::supervisor::bridge::tests")
    assert summary["baseline_exit"] == 0
    try:
        SOURCE.write_text(mutated)
        summary["mutant_exit"] = run("mutant", TEST, exact=True)
    finally:
        SOURCE.write_bytes(original)
        summary["source_sha256_restored"] = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
        summary["source_restored"] = SOURCE.read_bytes() == original
        (EVIDENCE / "preexec-results.json").write_text(json.dumps(summary, indent=2) + "\n")
    assert summary["source_restored"]
    log = (EVIDENCE / "preexec-mutant.log").read_text()
    assert summary["mutant_exit"] == 101
    assert "Some(ExecConfirmed)" in log
    assert "pre-exec death must not authorize" in log
    assert "test result: FAILED. 0 passed; 1 failed" in log
    summary["classification"] = "caught by regression assertion (false ExecConfirmed), not timeout"
    summary["restored_exit"] = run("restored", "adapters::supervisor::bridge::tests")
    (EVIDENCE / "preexec-results.json").write_text(json.dumps(summary, indent=2) + "\n")
    assert summary["restored_exit"] == 0
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
