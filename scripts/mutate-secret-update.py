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
JOURNAL = "src/write_journal.rs"
DATES = "src/secret_update_dates.rs"
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
        "let preview = plan_update(keys, &destination, &reviewed, &input, &now()?)?;",
        "let preview = crate::secret_update::UpdatePlan::default();")),
    "prompt-field-checked-before-secret": (UPDATE, (
        "        reviewed.require_password()?;\n", "")),
    "verified-only-after-comparison": (UPDATE, (
        "&& verify_updated(\n                    keys,\n                    &journal.destination,\n"
        "                    &fresh,\n                    &plan.body,\n                    &after,\n"
        "                    &input,\n                )\n                .is_ok()",
        "&& after.revision() != fresh.revision()")),
    "update-lock-taken": (UPDATE, (
        "let _lock = WriteJournal::lock_update(&root, &server, id)?;",
        "let _lock = ();")),
    "reconcile-unchanged-revision": (UPDATE, (
        "current.revision() == update.expected_revision",
        "current.revision().is_empty()")),
    "reconcile-moved-or-trashed": (UPDATE, (
        "let current = ItemSnapshot::parse(raw, id)?;\n        if journal",
        "let current = ItemSnapshot::parse(raw, id)?;\n"
        "        current.check_binding(keys, &journal.destination)?;\n        if journal")),
    "reconcile-valid-id": (UPDATE, (
        '        anyhow::ensure!(valid_id(id), "invalid item ID");\n'
        "        anyhow::ensure!(id == update.item_id",
        "        anyhow::ensure!(id == update.item_id")),
    "reconcile-exit-unless-verified": (UPDATE, (
        "journal.receipt.status == WriteStatus::Verified,\n"
        '        "update receipt is not verified',
        'true,\n        "update receipt is not verified')),
    "uncertain-blocks-item": (JOURNAL, (
        "if name.starts_with(&prefix) && name.ends_with(\".json\")",
        "if name.starts_with(\"never-\") && name.ends_with(\".json\")")),
    "lock-exclusive": (JOURNAL, (
        "fs4::FileExt::try_lock(&file).map_err(",
        "Ok::<(), fs4::TryLockError>(()).map_err(")),
    "lock-rechecks-uncertain": (JOURNAL, (
        "        Self::ensure_no_uncertain_update(root, server, item_id)?;\n"
        "        Ok(UpdateLock",
        "        Ok(UpdateLock")),
    "journal-server-normalized": (JOURNAL, (
        "let server = normalized_server(server);",
        "let server = server.trim_end_matches('/').to_owned();")),
    "server-revision-precondition": (CORE, (
        "Value::String(snapshot.revision.clone()),",
        "Value::Null,")),
    "replaceable-field-kinds": (CORE, (
        "Some(0 | 1)),", "Some(0..=2)),")),
    "password-history-entry": (CORE, (
        "added.insert(0, history_entry(&keys, &old, now)?);",
        "drop(history_entry(&keys, &old, now)?);")),
    "password-revision-date": (CORE, (
        'login.insert("passwordRevisionDate".into(), Value::String(now.to_owned()));',
        "")),
    "history-only-for-changed-password": (CORE, (
        "if !old.is_empty() && *old != *password {",
        "if !old.is_empty() {")),
    "hidden-field-history-entry": (CORE, (
        "added.insert(0, history_entry(&keys, &entry, now)?);",
        "drop(entry);")),
    "history-limit": (CORE, (
        "added.truncate(PASSWORD_HISTORY_LIMIT);",
        "added.truncate(PASSWORD_HISTORY_LIMIT + 1);")),
    "selected-value-exact": (CORE, (
        "*selected_value(&after.cipher, &keys, selector)? == *expected,",
        "selected_value(&after.cipher, &keys, selector).is_ok(),")),
    "identity-preserved": (CORE, (
        'ensure!(same, "preserved component changed");',
        'ensure!(same || true, "preserved component changed");')),
    "whole-login-compared": (CORE, (
        "(Some(sent), Some(stored)) => dates::same_json(&sent, &stored),",
        "(Some(_), Some(_)) => true,")),
    "dates-compared-as-instants": (DATES, (
        "(Some(sent), Some(stored)) => sent == stored,",
        "(Some(_), Some(_)) => true,")),
    "selected-field-object-compared": (CORE, (
        'without(Some(old), &["value"]) == without(Some(new), &["value"]),',
        "old.is_object(),")),
    "unselected-field-preserved": (CORE, (
        'None => ensure!(old == new, "preserved component changed"),',
        'None => ensure!(old.is_object(), "preserved component changed"),')),
    "attachments-compared": (CORE, (
        "attachments(before) == attachments(after),",
        "attachments(before).is_some() || true,")),
    "camel-case-shape-only": (CORE, (
        ".all(|key| !key.starts_with(|c: char| c.is_ascii_uppercase())),",
        ".all(|key| !key.is_empty()),")),
    "send-error-uncertain": ("src/api.rs", (
        "            .json(body)\n            .send()\n            .await\n"
        "            .map_err(|_error| WriteStatus::Uncertain)?;",
        "            .json(body)\n            .send()\n            .await\n"
        "            .map_err(|_error| WriteStatus::Failed)?;")),
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
