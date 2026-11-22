#!/usr/bin/env python3
"""Trusted `update` (issue 48) guard mutations; exact restore and baseline retest.

Each mutation removes or weakens one guard and must make the focused tests fail.
Usage: python3 scripts/mutate-secret-update.py EVIDENCE_DIR
Honors CARGO_BUILD_JOBS and RUSTUP_TOOLCHAIN from the environment.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
evidence = Path(sys.argv[1]).resolve()
evidence.mkdir(parents=True, exist_ok=True)
UPDATE = "src/commands/update.rs"
CORE = "src/secret_update.rs"
mutations = {
    "challenge-answer": ("src/commands.rs", (
        'anyhow::ensure!(answer == expected, "{denied}");',
        'anyhow::ensure!(!answer.is_empty() || answer == expected, "{denied}");')),
    "expected-revision-pin": (UPDATE, (
        "is_none_or(|expected| expected == reviewed.revision())",
        "is_none_or(|expected| !expected.is_empty())")),
    "review-revision-recheck": (UPDATE, (
        "fresh.revision() == reviewed.revision(),",
        "!fresh.revision().is_empty(),")),
    "fields-checked-before-decision": (UPDATE, (
        "    plan_update(keys, &destination, &reviewed, &input)?;\n",
        "")),
    "verified-only-after-comparison": (UPDATE, (
        "&& verify_updated(keys, &journal.destination, &fresh, &after, &input).is_ok()",
        "&& after.revision() != fresh.revision()")),
    "reconcile-unchanged-revision": (UPDATE, (
        "current.revision() == update.expected_revision",
        "current.revision().is_empty()")),
    "uncertain-blocks-item": ("src/write_journal.rs", (
        "if name.starts_with(&prefix) && name.ends_with(\".json\")",
        "if name.starts_with(\"never-\") && name.ends_with(\".json\")")),
    "server-revision-precondition": (CORE, (
        "Value::String(snapshot.revision.clone()),",
        "Value::Null,")),
    "replaceable-field-kinds": (CORE, (
        "Some(0 | 1)),", "Some(0..=2)),")),
    "selected-value-exact": (CORE, (
        "*selected_value(&after.cipher, &keys, selector)? == *expected,",
        "selected_value(&after.cipher, &keys, selector).is_ok(),")),
    "identity-preserved": (CORE, (
        "before.raw.get(member) == after.raw.get(member),",
        "before.raw.contains_key(member) || true,")),
    "unselected-field-preserved": (CORE, (
        'old.get("value") == new.get("value"),',
        'old.get("value").is_some(),')),
    "camel-case-shape-only": (CORE, (
        ".all(|key| !key.starts_with(|c: char| c.is_ascii_uppercase())),",
        ".all(|key| !key.is_empty()),")),
    "response-identity": ("src/api.rs", (
        "if value.get(\"id\").and_then(serde_json::Value::as_str) != Some(cipher_id) {",
        "if value.get(\"id\").is_none() {")),
}
originals = {file: (root / file).read_bytes() for file, _ in mutations.values()}
cargo = ["cargo", "test", "--locked", "--offline"]
commands = [
    cargo + ["--lib", "--", "secret_update", "write_journal", "--test-threads=1"],
    cargo + ["--test", "secret_update", "--test", "api_client", "--", "--test-threads=1"],
]


def run(name):
    code = 0
    with (evidence / f"{name}.log").open("wb") as log:
        for command in commands:
            result = subprocess.run(
                ["bash", "scripts/with-secure-test-tmpdir.sh", *command],
                cwd=root, stdout=log, stderr=subprocess.STDOUT, timeout=900)
            code = code or result.returncode
    return code


report = {"source_sha256": {n: hashlib.sha256(b).hexdigest() for n, b in originals.items()},
          "mutations": {}}
try:
    if run("baseline") != 0:
        raise RuntimeError("update baseline failed")
    for name, (file, (old, new)) in mutations.items():
        original = originals[file].decode()
        if original.count(old) != 1:
            raise RuntimeError(f"{name}: expected exactly one anchor")
        (root / file).write_text(original.replace(old, new))
        code = run(name)
        log = (evidence / f"{name}.log").read_text()
        caught = code != 0 and "test result: FAILED" in log and "could not compile" not in log
        report["mutations"][name] = {"caught_by_test": caught, "exit_code": code}
        (root / file).write_bytes(originals[file])
        print(f"{name}: {'caught' if caught else 'ESCAPED'}", flush=True)
        if not caught:
            raise RuntimeError(f"{name}: escaped or failed compilation")
finally:
    for file, original in originals.items():
        (root / file).write_bytes(original)
    report["restored_sha256"] = {n: hashlib.sha256((root / n).read_bytes()).hexdigest()
                                 for n in originals}
    report["restored_test_exit"] = run("restored")
    (evidence / "report.json").write_text(json.dumps(report, indent=2) + "\n")
if report["restored_test_exit"] != 0:
    raise SystemExit("restored baseline failed")
