#!/usr/bin/env python3
"""Mutate only the task-owned staged Swift package, never installed/shared code."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

stage = Path(sys.argv[1]).resolve()
evidence = Path(sys.argv[2]).resolve()
source = stage / "Sources/CompanionCore/Trust.swift"
original = source.read_bytes()
evidence.mkdir(parents=True, exist_ok=True)
mutations = {
    "leaf-pin": ("KeychainIdentity.fingerprintDER(SecCertificateCopyData(leaf) as Data) == configuration.leafSHA256", "(SecCertificateCopyData(leaf) as Data) != Data()"),
    "ca-hostname-validity": ("SecTrustEvaluateWithError(trust, nil),", "true,"),
}

def run(name):
    with (evidence / f"{name}.log").open("wb") as log:
        return subprocess.run(["swift", "test", "--package-path", str(stage)], stdout=log, stderr=subprocess.STDOUT, timeout=180).returncode

report = {"source_sha256": hashlib.sha256(original).hexdigest(), "mutations": {}}
try:
    if run("baseline") != 0:
        raise RuntimeError("native baseline failed")
    for name, (old, new) in mutations.items():
        if original.decode().count(old) != 1:
            raise RuntimeError(f"{name}: mutation anchor not unique")
        source.write_text(original.decode().replace(old, new))
        code = run(name)
        log = (evidence / f"{name}.log").read_text()
        caught = code != 0 and "Test Suite" in log and "failed" in log and "error: emit-module" not in log
        report["mutations"][name] = {"exit_code": code, "caught_by_test": caught}
        source.write_bytes(original)
        if not caught:
            raise RuntimeError(f"{name}: escaped or did not reach tests")
finally:
    source.write_bytes(original)
    report["restored_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
    report["restored_test_exit"] = run("restored")
    (evidence / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
if report["restored_test_exit"] != 0:
    raise SystemExit("restored native baseline failed")
