#!/usr/bin/env python3
"""Linux identity-management security mutations; compilation failures never count.

Run in an isolated checkout without concurrent builds/edits. Full root gates are
independent; this runner targets the new authenticated transport/core regressions.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
MUTATIONS = {
    "explicit-administrator": ("src/adapters/companion/management.rs", [("if !identity::administrator(&service.identity_store, actor) {", "if false {")]),
    "exact-target": ("src/adapters/companion/management.rs", [("&& t.target == target", "&& true")]),
    "exact-action": ("src/adapters/companion/management.rs", [("&& t.action_id == action_id", "&& true")]),
    "authority-generation": ("src/access/application.rs", [(".is_none_or(|a| a.generation != generation)", ".is_none_or(|_| false)")]),
    "lock-intent-epoch": ("src/access/application.rs", [("|| self.revocation_epoch.load(Ordering::Acquire) != epoch", "|| false")]),
    "status-target": ("src/adapters/companion/management.rs", [("action.actor == actor && action.target == target", "action.actor == actor")]),
    "authenticated-origin": ("src/access/provider.rs", [(".filter(|_| record.replay_digest.is_some())", ".filter(|_| true)")]),
    # Production Touch ID approval v2 (issue 49 PR A). Cross-platform tests
    # (`biometric_*`), so these also run on native macOS.
    "biometric-transcript-domain": ("src/access/approval_v2.rs", [("        APPROVAL_DOMAIN,\n", "        &b\"dev.vaultwarden.companion.synthetic.v1\"[..],\n")]),
    "biometric-transcript-generation": ("src/access/approval_v2.rs", [("&generation.to_be_bytes(),", "&0u64.to_be_bytes(),")]),
    "biometric-transcript-ticket-deadline": ("src/access/approval_v2.rs", [("&context.ticket_deadline_unix_ms.to_be_bytes(),", "&0u64.to_be_bytes(),")]),
    "biometric-transcript-review-digest": ("src/access/approval_v2.rs", [("        &review,\n", "        &[0u8; 32],\n")]),
    "biometric-key-id-check": ("src/access/direct_request.rs", [("|| proof.key_id != enrolled.key_id", "|| false")]),
    "biometric-require-password": ("src/access/direct_request.rs", [("if self.password_required", "if false")]),
    "biometric-both-password-and-proof": ("src/adapters/companion.rs", [("(Decision::Approve, Some(p), None) => valid_password(p),", "(Decision::Approve, Some(p), _) => valid_password(p),")]),
    "biometric-neither-password-nor-proof": ("src/adapters/companion.rs", [("(Decision::Deny, None, None) => true,", "(_, None, None) => true,")]),
    "biometric-current-key-recheck": ("src/adapters/companion.rs", [("&& identity::biometric_key(&self.identity_store, device)", "&& false && identity::biometric_key(&self.identity_store, device)")]),
    "biometric-retired-key": ("src/adapters/companion_identity.rs", [("|| registry.retired_biometric_keys.contains(&key_id)", "|| false")]),
    "biometric-ticket-purpose": ("src/adapters/companion/management.rs", [("&& t.purpose == purpose", "&& true")]),
    "biometric-ticket-exact-action": ("src/adapters/companion/management.rs", [("&& t.action_id == expected_action", "&& true")]),
    "biometric-ticket-exact-target": ("src/adapters/companion/management.rs", [("&& t.target == *expected_target", "&& true")]),
    "biometric-ticket-one-per-actor": ("src/adapters/companion/management.rs", [("&& !(t.actor == actor && t.purpose == Purpose::Biometric(operation))", "")]),
    "biometric-own-device-enroll": ("src/adapters/companion/management.rs", [("&& (target.id == actor", "&& (true")]),
}
BIOMETRIC = [name for name in MUTATIONS if name.startswith("biometric-")]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--only", choices=list(MUTATIONS), nargs="+")
    args = parser.parse_args()
    if sys.platform == "darwin":
        # Only the biometric tests compile on macOS; the other suites are Linux-only.
        names = args.only or BIOMETRIC
        if any(name not in BIOMETRIC for name in names):
            raise SystemExit("on macOS only the biometric-* mutations have compiled tests")
    elif sys.platform.startswith("linux"):
        names = args.only or list(MUTATIONS)
    else:
        raise SystemExit("identity-management mutations require Linux or native macOS")
    selected = {name: MUTATIONS[name] for name in names}
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    originals = {file: (ROOT / file).read_bytes() for file, _ in selected.values()}
    report = {"source_sha256": {file: hashlib.sha256(raw).hexdigest() for file, raw in originals.items()}, "mutations": {}}
    command = [str(ROOT / "scripts/with-secure-test-tmpdir.sh"), "cargo", "test", "--offline", "--locked", "--lib"]

    def run(name, compile_only=False):
        with (evidence / f"{name}.log").open("wb") as log:
            return subprocess.run(command + (["--no-run"] if compile_only else ["--", "management_", "biometric_", "--test-threads=1"]), cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, timeout=600).returncode

    try:
        if run("baseline") != 0:
            raise RuntimeError("pristine baseline failed")
        for name, (file, replacements) in selected.items():
            path = ROOT / file
            if path.read_bytes() != originals[file]:
                raise RuntimeError("concurrent source edit detected before mutation")
            changed = originals[file].decode()
            for old, new in replacements:
                if changed.count(old) != 1:
                    raise RuntimeError(f"{name}: expected one exact mutation site")
                changed = changed.replace(old, new)
            path.write_text(changed)
            try:
                compiled = run(f"{name}-compile", compile_only=True)
                result = run(name) if compiled == 0 else None
                log = (evidence / f"{name}.log").read_text() if result is not None else ""
                caught = compiled == 0 and result != 0 and "test result: FAILED" in log and "could not compile" not in log
                report["mutations"][name] = {"compile_exit": compiled, "test_exit": result, "caught_by_test": caught}
                if not caught:
                    raise RuntimeError(f"{name}: survived or failed compilation/infrastructure")
            finally:
                path.write_bytes(originals[file])
    finally:
        report["restored_sha256"] = {file: hashlib.sha256((ROOT / file).read_bytes()).hexdigest() for file in originals}
        if report["restored_sha256"] != report["source_sha256"]:
            raise RuntimeError("exact source restoration failed")
        report["restored_test_exit"] = run("restored")
        (evidence / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    if report["restored_test_exit"] != 0:
        raise SystemExit("restored baseline failed")


if __name__ == "__main__":
    main()
