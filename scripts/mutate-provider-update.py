#!/usr/bin/env python3
"""Protected provider `update` (issue 48 phase 2) guard mutations.

Each mutation removes or weakens one guard and must make the focused tests
fail; sources are restored exactly and the baseline is retested.
Usage: python3 scripts/mutate-provider-update.py EVIDENCE_DIR
Runs on Linux and on native macOS. Honors CARGO_BUILD_JOBS and RUSTUP_TOOLCHAIN;
BUILD_LOCK=PATH serializes each test command with other builds on the host.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
evidence = Path(sys.argv[1]).resolve()
evidence.mkdir(parents=True, exist_ok=True)
POLICY = "src/access/policy.rs"
EFFECT = "src/access/policy/update.rs"
APP = "src/access/application.rs"
WRITE = "src/access/application/update.rs"
PROVIDER = "src/access/provider.rs"
ADAPTER = "src/adapters/vaultwarden/update.rs"
COMPANION = "src/adapters/companion.rs"
CORE_PROTOCOL = "companion/rust/src/provider/protocol.rs"
CORE_SESSION = "companion/rust/src/provider/session.rs"
mutations = {
    # Policy and review binding.
    "policy-exclusive-with-create": (POLICY, (
        "            && draft.create.is_none()\n            && draft.ssh.is_none()\n"
        "            && draft.credentials.is_empty()\n            && draft.targets.is_empty()\n"
        "            && draft.arguments.is_empty()\n            && update.valid()",
        "            && draft.ssh.is_none()\n"
        "            && draft.credentials.is_empty()\n            && draft.targets.is_empty()\n"
        "            && draft.arguments.is_empty()\n            && update.valid()")),
    "policy-refuses-marker-field": (EFFECT, (
        "valid_field_name(name) && name != \"vw-access\"",
        "valid_field_name(name)")),
    "policy-notes-only-allowed": (EFFECT, (
        "(matches!(f.as_str(), \"password\" | \"notes\")",
        "(matches!(f.as_str(), \"password\")")),
    "review-revision-validated": (POLICY, (
        "(Some(effect), Some(revision)) if update::valid_revision(revision) => {",
        "(Some(effect), Some(revision)) => {")),
    "review-revision-bounded": (EFFECT, (
        "!value.is_empty() && value.len() <= MAX_REVISION_LEN",
        "value.len() <= MAX_REVISION_LEN + 1")),
    # Application: stale approvals and the one-shot write.
    "stale-before-producer": (APP, (
        "                Self::update_still_reviewed(&mut authority, &review)?;\n",
        "                drop(Self::update_still_reviewed(&mut authority, &review));\n")),
    "stale-before-approval": (APP, (
        "                current?;\n", "                drop(current);\n")),
    "producer-schema-exact": (WRITE, (
        "if input.selectors() != review.effect().sorted_fields() {",
        "if input.selectors().is_empty() {")),
    "uncertain-update-blocks-item": (PROVIDER, (
        "if Self::update_uncertain(&state, &binding.request_id, update) {",
        "if Self::update_uncertain(&state, &binding.request_id, update) && false {")),
    "reconcile-rewrites-only-uncertain": (PROVIDER, (
        "                if receipt.status == WriteStatus::Uncertain {\n                    receipt.status = status;",
        "                if receipt.status != WriteStatus::Failed {\n                    receipt.status = status;")),
    "verified-only-after-comparison": (WRITE, (
        "                        .verify_update(review, &prepared, &input)\n                        .is_err()",
        "                        .verify_update(review, &prepared, &input)\n                        .is_err()\n                        && false")),
    # Adapter: revision, schema, binding and PUT outcome rules.
    "adapter-revision-recheck": (ADAPTER, (
        "if fresh.revision() != review.expected_revision {",
        "if fresh.revision().is_empty() {")),
    "adapter-schema-exact": (ADAPTER, (
        "if input.selectors() != effect.sorted_fields() {",
        "if input.selectors().is_empty() {")),
    "adapter-body-bound-to-revision": (ADAPTER, (
        "        if prepared.before().revision() != review.expected_revision\n            || prepared",
        "        if prepared.before().revision().is_empty()\n            || prepared")),
    "adapter-no-put-once-not-live": (ADAPTER, (
        "        if !live() {\n            return Err(WriteStatus::Failed);\n        }\n        let response",
        "        let response")),
    "adapter-definite-rejections": (ADAPTER, (
        "if matches!(status.as_u16(), 400 | 401 | 403 | 404 | 405 | 422) {",
        "if matches!(status.as_u16(), 401 | 403 | 405) {")),
    "adapter-response-identity": (ADAPTER, (
        "!= Some(effect.item_id.as_str()) {",
        "== Some(\"never\") {")),
    "adapter-binding-checked": (ADAPTER, (
        "        let snapshot = self.read_item(effect)?;\n        snapshot\n"
        "            .check_binding(keys, &effect.destination)\n"
        "            .map_err(|_error| SessionError::BackendUnavailable)?;\n        Ok(snapshot)",
        "        let snapshot = self.read_item(effect)?;\n        Ok(snapshot)")),
    "adapter-reconcile-unchanged-binding": (ADAPTER, (
        "            current\n                .check_binding(keys, &effect.destination)\n"
        "                .map_err(|_error| SessionError::BackendUnavailable)?;\n            Ok(WriteStatus::Failed)",
        "            Ok(WriteStatus::Failed)")),
    "adapter-reconcile-revision": (ADAPTER, (
        "if current.revision() == review.expected_revision {",
        "if !current.revision().is_empty() {")),
    # Companion capability (provider side).
    "capability-required": (COMPANION, (
        "                        if ticket.review.update.is_some()\n                            && !capabilities",
        "                        if ticket.review.update.is_some()\n                            && false\n                            && !capabilities")),
    "capability-exact-name": (COMPANION, (
        ".any(|name| name == UPDATE_REVIEW_CAPABILITY)",
        ".any(|name| name.starts_with(\"update-review.\"))")),
    "capability-shape-validated": (COMPANION, (
        "                            && valid_capabilities(names)\n",
        "                            && !names.is_empty()\n")),
    "capability-approve-only": (COMPANION, (
        "                            && matches!(decision, Decision::Approve)\n",
        "")),
    # Companion core (client side).
    "core-update-block-validated": (CORE_PROTOCOL, (
        "            && self.update.as_ref().is_none_or(UpdateReview::valid)\n", "")),
    "core-password-asserts-capability": (CORE_SESSION, (
        "                if command == Command::Approve && review.response.review.update.is_some() {",
        "                if command == Command::Approve && review.response.review.update.is_none() {")),
    "core-touch-id-asserts-capability": (CORE_SESSION, (
        "        if review.response.review.update.is_some() {\n            request[\"capabilities\"]",
        "        if review.response.review.update.is_none() {\n            request[\"capabilities\"]")),
}
originals = {file: (root / file).read_bytes() for file, _ in mutations.values()}
cargo = ["cargo", "test", "--locked", "--offline"]
commands = [
    cargo + ["--lib", "--", "update", "--test-threads=1"],
    cargo + ["--manifest-path", "companion/rust/Cargo.toml", "--test", "update_review"],
]


def run(name):
    code = 0
    with (evidence / f"{name}.log").open("wb") as log:
        for command in commands:
            lock = os.environ.get("BUILD_LOCK")
            prefix = ["/usr/bin/lockf", "-k", lock] if lock else []
            result = subprocess.run(
                [*prefix, "bash", "scripts/with-secure-test-tmpdir.sh", *command],
                cwd=root, stdout=log, stderr=subprocess.STDOUT, timeout=1800)
            code = code or result.returncode
    return code


report = {"source_sha256": {n: hashlib.sha256(b).hexdigest() for n, b in originals.items()},
          "mutations": {}}
try:
    if run("baseline") != 0:
        raise RuntimeError("provider update baseline failed")
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
