#!/usr/bin/env python3
"""Eight scoped harness mutations; each must compile, fail tests, and restore.

No services or ignored acceptance tests run. Do not edit/build concurrently.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

repo = Path(__file__).resolve().parents[1]
source = repo / "tests/support/real_vaultwarden_pilot.rs"
original = source.read_bytes()
evidence = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else repo / "target/pilot-mutations"
evidence.mkdir(parents=True, exist_ok=True)
command = [str(repo / "scripts/with-secure-test-tmpdir.sh"), "cargo", "test", "--locked", "--test", "protected_rehearsal", "support::pilot::tests::", "--", "--test-threads=1"]
mutations = {
    "poll_busy": ('Err(error) if error.is::<BusyPoll>() => {}', 'Err(error) if error.is::<BusyPoll>() => return Err(error)'),
    "readiness": ('if observed.is_none() {\n            return Ok(false);\n        } // mutation: readiness', 'if observed.is_none() {\n            return Ok(true);\n        } // mutation: readiness'),
    "duplicate": ('ensure!(!self.consumed, "pilot submission already consumed"); // mutation: duplicate', '// mutation: duplicate disabled'),
    "counts": ('ensure!(\n            starts == usize::from(*approve) && successes == usize::from(*approve),\n            "pilot execution count mismatch"\n        ); // mutation: counts', 'let _ = (starts, successes); // mutation: counts disabled'),
    "redaction": ('run.observe(bytes)?; // mutation: redaction', 'let _ = (run, bytes); // mutation: redaction disabled'),
    "cleanup": ('observation.verify()?; // mutation: cleanup', 'let _ = observation; // mutation: cleanup disabled'),
    "failure_evidence": ('observation.emit(run, error, writer) // mutation: failure evidence', 'let _ = (observation, error, writer); Ok::<(), anyhow::Error>(()) // mutation: failure evidence disabled'),
    "binary_redaction_fragments": ('if bytes.starts_with(b"-----BEGIN ") {', 'if true { // deliberately split binary data into false-positive fragments'),
}

def run(name):
    with (evidence / f"{name}.log").open("wb") as log:
        return subprocess.run(command, cwd=repo, stdout=log, stderr=subprocess.STDOUT, timeout=300).returncode

report = {"source_sha256": hashlib.sha256(original).hexdigest(), "mutations": {}}
try:
    if run("baseline") != 0:
        raise RuntimeError("baseline failed")
    for name, (old, new) in mutations.items():
        text = original.decode()
        if text.count(old) != 1:
            raise RuntimeError(f"{name}: mutation anchor not unique")
        source.write_text(text.replace(old, new))
        code = run(name)
        output = (evidence / f"{name}.log").read_text()
        caught = code != 0 and "test result: FAILED" in output and "could not compile" not in output
        report["mutations"][name] = {"exit_code": code, "caught_by_test": caught}
        source.write_bytes(original)
        if not caught:
            raise RuntimeError(f"{name}: escaped or failed to compile")
finally:
    source.write_bytes(original)
    report["restored_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
    report["restored_test_exit"] = run("restored")
    (evidence / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
if report["restored_test_exit"] != 0:
    raise SystemExit("restored baseline failed")
