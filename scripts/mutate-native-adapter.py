#!/usr/bin/env python3
"""Targeted semantic faults for the macOS native adapter (#49).

Each fault is applied to a private copy of this working tree below a fresh
`$HOME` scratch directory (provider-owned ancestry, umask 077), never to the
checkout. A fault counts as caught only when its unmutated baseline passed and
the named test fails with `test result: FAILED`; build failures and timeouts
are reported, never counted. Usage: mutate-native-adapter.py EVIDENCE_DIR
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

if sys.platform != "darwin" or os.uname().machine != "arm64":
    raise SystemExit("native adapter faults require Apple Silicon macOS")
repository = Path(__file__).resolve().parents[1]
evidence = Path(sys.argv[1]).resolve()
if evidence.is_relative_to(repository):
    raise SystemExit("evidence directory must be outside the source repository")
evidence.mkdir(parents=True, exist_ok=True)
NATIVE = "src/adapters/native/"
# name: (file, old, new, detecting test filter)
FAULTS = {
    "release-race": (NATIVE + "mod.rs",
        "            control.release(&mut || {\n                pid = launch.start()?;\n                Ok(())\n            })?;",
        "            pid = launch.start()?;\n            control.release(&mut || Ok(()))?;",
        "adapters::native::tests::native_release_denial_does_not_launch_and_withdrawal_does_not_signal_consumer"),
    "implicit-termination": (NATIVE + "mod.rs",
        "        if pid > 0 {\n            prepared.reaping.detach(pid);",
        "        if pid > 0 {\n            unsafe { libc::kill(pid, libc::SIGKILL) };\n            prepared.reaping.detach(pid);",
        "adapters::native::tests::native_release_denial_does_not_launch_and_withdrawal_does_not_signal_consumer"),
    "peer-token-pid": (NATIVE + "mod.rs",
        "                && token[5] == self.pid\n",
        "",
        "adapters::ssh_agent::tests::same_uid_wrong_process_is_rejected_without_poisoning_next_peer"),
    "peer-cdhash": (NATIVE + "mod.rs",
        "                && image::dynamic(&token, &self.requirement).is_ok()\n",
        "",
        "adapters::ssh_agent::tests::native_correct_peer_pid_with_wrong_cdhash_denies_acceptance_and_final_release"),
    "loader-path": (NATIVE + "image.rs",
        'if &value[..terminator] != b"/usr/lib/dyld" {',
        "if false {",
        "adapters::native::image::tests::native_loader_profile_rejects_forbidden_unknown_and_malformed_commands"),
    "shared-cache-dependency": (NATIVE + "image.rs",
        "if !unsafe { _dyld_shared_cache_contains_path(name.as_ptr()) } {",
        "if false {",
        "adapters::native::image::tests::native_loader_profile_rejects_forbidden_unknown_and_malformed_commands"),
    "reaper-live-child": (NATIVE + "reaper.rs",
        "                            if result == pid\n",
        "                            if result != pid\n",
        "adapters::native::reaper::tests::foreign_reaped_pid_is_released_but_live_child_keeps_capacity_until_natural_exit"),
    "producer-before-reaping": (NATIVE + "producer.rs",
        "if evidence != CleanupEvidence::Reaped {",
        "if evidence == CleanupEvidence::NotStarted {",
        "adapters::native::tests::native_producer_output_requires_confirmed_reaping"),
    "producer-overflow-truncates": (NATIVE + "producer.rs",
        "            if received.filled > CAPACITY {\n                received.invalid = true;",
        "            if received.filled > CAPACITY {",
        "adapters::native::tests::native_producer_rejects_overflow_and_malformed_frames"),
    "identity-root-provider": (NATIVE + "identity.rs",
        "    if value.provider_uid == 0\n        || value.operator_uid == 0",
        "    if value.operator_uid == 0",
        "adapters::native::mutation_tests::native_installed_identities_reject_root_shared_or_unbound_accounts_and_relative_paths"),
    "no-writer-group-mode": (NATIVE + "platform.rs",
        "if metadata.mode() & 0o022 != 0\n            ||",
        "if metadata.mode() & 0o002 != 0\n            ||",
        "adapters::native::mutation_tests::native_no_writer_open_enforces_ownership_and_write_modes_per_component"),
}

os.umask(0o077)
scratch = Path(tempfile.mkdtemp(prefix=".vw-native-faults.", dir=os.environ["HOME"]))
os.chmod(scratch, 0o700)
source = scratch / "source"
tmp = scratch / "tmp"
tmp.mkdir(mode=0o700)
files = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
                       cwd=repository, check=True, capture_output=True).stdout.split(b"\0")
for name in filter(None, files):
    target = source / name.decode()
    target.parent.mkdir(parents=True, exist_ok=True)
    # Fresh mtimes: a shared target directory must never satisfy the build with an
    # artifact compiled from other (possibly mutated) bytes of the same package.
    shutil.copy(repository / name.decode(), target)
subprocess.run(["cargo", "fetch", "--locked"], cwd=source, check=True)
environment = dict(os.environ, TMPDIR=str(tmp), CARGO_NET_OFFLINE="true",
                   CARGO_PROFILE_DEV_DEBUG="0", CARGO_BUILD_JOBS="4")


def run(label, test):
    started = time.monotonic()
    with (evidence / f"{label}.log").open("wb") as log:
        try:
            code = subprocess.run(["cargo", "test", "--locked", "--lib", "--", "--exact", "--test-threads=1", test],
                                  cwd=source, env=environment, stdout=log, stderr=subprocess.STDOUT,
                                  timeout=600).returncode
        except subprocess.TimeoutExpired:
            code = "timeout"
    text = (evidence / f"{label}.log").read_text(errors="replace")
    return {"exit_code": code, "seconds": round(time.monotonic() - started, 1),
            "failed": "test result: FAILED" in text and "1 failed" in text,
            "passed": "test result: ok. 1 passed" in text}


report = {"repository_head": subprocess.run(["git", "rev-parse", "HEAD"], cwd=repository, check=True,
                                             capture_output=True, text=True).stdout.strip(),
          "faults": {}}
try:
    for name, (path, old, new, test) in FAULTS.items():
        file = source / path
        original = file.read_bytes()
        if original.decode().count(old) != 1:
            raise RuntimeError(f"{name}: mutation anchor not unique")
        baseline = run(f"{name}-baseline", test)
        file.write_text(original.decode().replace(old, new))
        mutant = run(f"{name}-mutant", test)
        file.write_bytes(original)
        report["faults"][name] = {
            "file": path, "test": test, "source_sha256": hashlib.sha256(original).hexdigest(),
            "restored_sha256": hashlib.sha256(file.read_bytes()).hexdigest(),
            "baseline": baseline, "mutant": mutant,
            "caught": baseline["passed"] and mutant["exit_code"] == 101 and mutant["failed"],
        }
finally:
    (evidence / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    shutil.rmtree(scratch, ignore_errors=True)
print(json.dumps({n: f["caught"] for n, f in report["faults"].items()}, indent=2))
if not all(f["caught"] for f in report["faults"].values()):
    raise SystemExit("a semantic fault escaped or did not reach its test")
