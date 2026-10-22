#!/usr/bin/env python3
"""Provider security mutations, exact source restoration and baseline retest.

Run without concurrent edits or builds. Each mutation must compile and fail a
test; a compiler error is not a caught mutation. No passwords/bodies are logged.
"""
import hashlib
import argparse
import json
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
base = root / "companion/rust/src/provider"
originals = {name: (base / name).read_bytes() for name in ["protocol.rs", "session.rs"]}
parser = argparse.ArgumentParser()
parser.add_argument("evidence", nargs="?", type=Path, default=root / "companion/build/provider-mutations")
parser.add_argument("--only", nargs="+")
args = parser.parse_args()
evidence = args.evidence.resolve()
evidence.mkdir(parents=True, exist_ok=True)
command = ["cargo", "test", "--locked", "--offline", "--manifest-path", str(root / "companion/rust/Cargo.toml")]
mutations = {
    "closed-schema": ("protocol.rs", [("#[serde(deny_unknown_fields)]\npub struct Credential", "pub struct Credential")]),
    "escaped-review": ("protocol.rs", [('_ => out.push_str(&format!("\\\\u{{{:04x}}}", c as u32)),', '_ => out.push(c),')]),
    "ticket-admission": ("session.rs", [("if !self.can_decide() {", "if false {")]),
    "stale-read": ("session.rs", [("if !decision && flight.epoch != self.epoch {", "if false {")]),
    "pending-uncertainty": ("session.rs", [("reply.status == (Status::Pending {})", "false")]),
    "request-scope": ("session.rs", [("command != Command::Status || id != *unresolved", "command != Command::Status || id.is_empty() && unresolved.is_empty()")]),
    "duplicate-completion": ("session.rs", [("struct Flight {", "#[derive(Clone)]\nstruct Flight {"), ('self.flight.take().expect("matched flight")', 'self.flight.clone().expect("matched flight")')]),
    "monotonic-expiry": ("session.rs", [("r.started.elapsed() < Duration::from_secs(55)", "true"), ("r.started.elapsed() >= Duration::from_secs(55)", "false")]),
    "wall-expiry": ("session.rs", [("unix_seconds() < r.response.review.expires_at_unix_seconds", "true"), ("unix_seconds() >= r.response.review.expires_at_unix_seconds", "false")]),
    "rejected-authority": ("session.rs", [("self.authority = None;\n                self.requests.clear();\n                self.outcome = ProviderOutcome::Rejected;", "self.outcome = ProviderOutcome::Rejected;")]),
    "typed-rejection": ("session.rs", [("self.outcome = ProviderOutcome::Rejected;", "self.outcome = ProviderOutcome::Accepted;")]),
    "committed-terminality": ("session.rs", [("Status::Approved {} | Status::Running {} => ProviderStatusProgress::Committed,", "Status::Approved {} | Status::Running {} => ProviderStatusProgress::Terminal,")]),
}
if args.only:
    mutations = {name: mutations[name] for name in args.only}

def run(name):
    with (evidence / f"{name}.log").open("wb") as log:
        for selection in [["--test", "provider"], ["--lib", "provider::session::tests"]]:
            code = subprocess.run(command + selection, cwd=root, stdout=log, stderr=subprocess.STDOUT, timeout=180).returncode
            if code != 0:
                return code
        return 0

report = {"source_sha256": {n: hashlib.sha256(b).hexdigest() for n, b in originals.items()}, "mutations": {}}
try:
    if run("baseline") != 0:
        raise RuntimeError("provider baseline failed")
    for name, (file, replacements) in mutations.items():
        changed = originals[file].decode()
        for old, new in replacements:
            if changed.count(old) != 1:
                raise RuntimeError(f"{name}: expected exactly one mutation target")
            changed = changed.replace(old, new)
        (base / file).write_text(changed)
        code = run(name)
        log = (evidence / f"{name}.log").read_text()
        caught = code != 0 and "test result: FAILED" in log and "could not compile" not in log
        report["mutations"][name] = {"exit_code": code, "caught_by_test": caught}
        (base / file).write_bytes(originals[file])
        if not caught:
            raise RuntimeError(f"{name}: escaped or failed compilation")
finally:
    for name, content in originals.items():
        (base / name).write_bytes(content)
    report["restored_sha256"] = {n: hashlib.sha256((base / n).read_bytes()).hexdigest() for n in originals}
    report["restored_test_exit"] = run("restored")
    (evidence / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
if report["restored_test_exit"] != 0:
    raise SystemExit("restored provider baseline failed")
