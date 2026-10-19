#!/usr/bin/env python3
"""One-at-a-time security mutations; exact restoration even after test failure.

Run only with no concurrent edits/builds of the companion crate. Evidence contains
test names and statuses, never native keys, messages or signatures.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
source = root / "companion/rust/src/lifecycle.rs"
original = source.read_bytes()
evidence = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else root / "companion/build/mutations"
evidence.mkdir(parents=True, exist_ok=True)
command = ["cargo", "test", "--locked", "--offline", "--manifest-path", str(root / "companion/rust/Cargo.toml")]
mutations = {
    "verification": [("if key.verify(&active.transcript, &signature).is_err()", "if false")],
    "binding": [("&work.nonce,", "&[0; 32],")],
    "expiry": [("if Instant::now() >= active.deadline || unix_ms() >= active.work.expires_unix_ms", "if false")],
    "cancellation": [("if active.invalidated || active.work.epoch != self.epoch", "if false")],
    "duplicates": [("struct Active {", "#[derive(Clone)]\nstruct Active {"),
                   ('self.active.take().expect("matched active worker")', 'self.active.as_ref().cloned().expect("matched active worker")')],
    "admission": [("if self.active.is_some() {", "if false {"),
                  ("can_sign: self.active.is_none() && self.key.is_some() && fresh,", "can_sign: self.key.is_some() && fresh,")],
}

def run(name):
    with (evidence / f"{name}.log").open("wb") as log:
        result = subprocess.run(command, cwd=root, stdout=log, stderr=subprocess.STDOUT, timeout=180)
    return result.returncode

report = {"source_sha256": hashlib.sha256(original).hexdigest(), "mutations": {}}
try:
    if run("baseline") != 0:
        raise RuntimeError("baseline does not pass")
    for name, replacements in mutations.items():
        changed = original.decode()
        for old, new in replacements:
            if changed.count(old) != 1:
                raise RuntimeError(f"{name}: expected exactly one mutation target")
            changed = changed.replace(old, new)
        source.write_text(changed)
        code = run(name)
        log = (evidence / f"{name}.log").read_text()
        caught = code != 0 and "test result: FAILED" in log and "could not compile" not in log
        report["mutations"][name] = {"exit_code": code, "caught_by_test": caught}
        source.write_bytes(original)
        if not caught:
            raise RuntimeError(f"mutation {name} escaped or failed to compile")
finally:
    source.write_bytes(original)
    report["restored_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
    report["restored_test_exit"] = run("restored")
    (evidence / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))

if report["restored_test_exit"] != 0:
    raise SystemExit("restored baseline failed")
