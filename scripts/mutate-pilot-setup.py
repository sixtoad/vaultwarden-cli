#!/usr/bin/env python3
"""Attributable disposable setup mutations; exact restoration and opt-in retest."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
source = root / "companion/lib/provider/controller.dart"
original = source.read_bytes()
evidence = Path(sys.argv[1]).resolve()
evidence.mkdir(parents=True, exist_ok=True)
mutations = {
    "setup-recovery-admission": (
        "if (!canSetupPilot) return; // mutation: pilot recovery admission",
        "if (!disposablePilotEnabled) return; // deliberately bypass setup/recovery admission",
        "unresolved decision, committed request and busy operation block replacement",
    ),
    "failed-import-unlock": (
        "if (!imported || !eligible || context != _context) {",
        "if (!imported) { _ready = true; imported = true; }\n    if (!eligible || context != _context) {",
        "failed import or mismatched identity never sends any follow-on command",
    ),
    "identity-verification": (
        "installed.fingerprint != bundle.fingerprint",
        "false",
        "failed import or mismatched identity never sends any follow-on command",
    ),
}


def run(name, test=None):
    command = ["flutter", "test", "--no-pub", "--reporter=expanded",
               "--dart-define=COMPANION_DISPOSABLE_PILOT=true", "test/pilot_setup_test.dart"]
    if test:
        command.extend(["--plain-name", test])
    with (evidence / f"{name}.log").open("wb") as log:
        return subprocess.run(command, cwd=root / "companion", stdout=log,
                              stderr=subprocess.STDOUT, timeout=180).returncode


report = {"source_sha256": hashlib.sha256(original).hexdigest(), "mutations": {}}
try:
    if run("baseline") != 0:
        raise RuntimeError("pilot setup baseline failed")
    for name, (old, new, test) in mutations.items():
        if original.decode().count(old) != 1:
            raise RuntimeError(f"{name}: unexpected anchor count")
        source.write_text(original.decode().replace(old, new))
        code = run(name, test)
        log = (evidence / f"{name}.log").read_text()
        caught = code != 0 and "[E]" in log and "Compilation failed" not in log and "Failed to load" not in log
        report["mutations"][name] = {"exit_code": code, "caught_by_test": caught, "test": test}
        source.write_bytes(original)
        if not caught:
            raise RuntimeError(f"{name}: escaped or failed before assertions")
finally:
    source.write_bytes(original)
    report["restored_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
    report["restored_test_exit"] = run("restored")
    (evidence / "report.json").write_text(json.dumps(report, indent=2) + "\n")
if report["restored_test_exit"] != 0:
    raise SystemExit("restored pilot tests failed")
