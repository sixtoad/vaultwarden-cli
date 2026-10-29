#!/usr/bin/env python3
"""Linux history endpoint security mutations; exact restore and baseline retest."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
if sys.platform != "linux":
    raise SystemExit("History endpoint runtime verification requires Linux")
evidence = Path(sys.argv[1]).resolve()
evidence.mkdir(parents=True, exist_ok=True)
mutations = {
    "revocation-after-read": ("src/adapters/companion.rs", (
        "if !self.authorized(device) {\n                        return Response::error(Error::Unauthorized);",
        "if false {\n                        return Response::error(Error::Unauthorized);")),
    "owner-filter": ("src/access/provider.rs", (
        ".filter(|d| d.human_visible(owner, self.owner_uid()))\n            .flat_map(|d| d.audit)",
        ".filter(|_| true)\n            .flat_map(|d| d.audit)")),
    "canonical-maximum": ("src/access/history.rs", (
        "pub const MAX_HISTORY_LIMIT: u32 = 200;", "pub const MAX_HISTORY_LIMIT: u32 = 201;")),
    "canonical-default": ("src/access/history.rs", (
        "pub const DEFAULT_HISTORY_LIMIT: u32 = 50;", "pub const DEFAULT_HISTORY_LIMIT: u32 = 49;")),
}
originals = {name: (root / name).read_bytes() for name, _ in mutations.values()}
command = ["bash", "scripts/with-secure-test-tmpdir.sh", "cargo", "test", "--locked", "--offline", "--lib", "companion_history_"]

def run(name):
    with (evidence / f"{name}.log").open("wb") as log:
        return subprocess.run(command, cwd=root, stdout=log, stderr=subprocess.STDOUT, timeout=300).returncode

report = {"source_sha256": {n: hashlib.sha256(b).hexdigest() for n, b in originals.items()}, "mutations": {}}
try:
    if run("baseline") != 0:
        raise RuntimeError("history endpoint baseline failed")
    for name, (file, (old, new)) in mutations.items():
        original = originals[file].decode()
        if original.count(old) != 1:
            raise RuntimeError(f"{name}: expected one anchor")
        (root / file).write_text(original.replace(old, new))
        code = run(name)
        log = (evidence / f"{name}.log").read_text()
        caught = code != 0 and "test result: FAILED" in log and "could not compile" not in log
        report["mutations"][name] = {"caught_by_test": caught, "exit_code": code}
        (root / file).write_bytes(originals[file])
        if not caught:
            raise RuntimeError(f"{name}: escaped or failed compilation")
finally:
    for file, original in originals.items():
        (root / file).write_bytes(original)
    report["restored_sha256"] = {n: hashlib.sha256((root / n).read_bytes()).hexdigest() for n in originals}
    report["restored_test_exit"] = run("restored")
    (evidence / "report.json").write_text(json.dumps(report, indent=2) + "\n")
if report["restored_test_exit"] != 0:
    raise SystemExit("restored baseline failed")
