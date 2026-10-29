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
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--only", choices=list(MUTATIONS), nargs="+")
    args = parser.parse_args()
    if not sys.platform.startswith("linux"):
        raise SystemExit("identity-management mutations require Linux (provider is cfg-disabled elsewhere)")
    selected = {name: MUTATIONS[name] for name in args.only or MUTATIONS}
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    originals = {file: (ROOT / file).read_bytes() for file, _ in selected.values()}
    report = {"source_sha256": {file: hashlib.sha256(raw).hexdigest() for file, raw in originals.items()}, "mutations": {}}
    command = [str(ROOT / "scripts/with-secure-test-tmpdir.sh"), "cargo", "test", "--offline", "--locked", "--lib"]

    def run(name, compile_only=False):
        with (evidence / f"{name}.log").open("wb") as log:
            return subprocess.run(command + (["--no-run"] if compile_only else ["management_", "--", "--test-threads=1"]), cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, timeout=600).returncode

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
