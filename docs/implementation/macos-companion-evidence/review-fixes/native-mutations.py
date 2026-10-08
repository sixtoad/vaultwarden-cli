#!/usr/bin/env python3
"""Run scoped native review-fix mutations in a disposable macOS source snapshot.

Requires an explicitly finalized plan and a source-manifest.json with exact hashes.
Never use against the shared checkout. No app launch/install or OS settings changes.
Native test fixtures temporarily use isolated Keychains; run sequentially per user.
"""
import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time


def sha(data):
    return hashlib.sha256(data).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def contained(root, relative):
    candidate = root / relative
    if Path(relative).is_absolute() or ".." in Path(relative).parts or candidate.is_symlink():
        raise ValueError("Unsafe plan path: " + relative)
    resolved = candidate.resolve(strict=True)
    if root not in resolved.parents:
        raise ValueError("Plan path escaped snapshot: " + relative)
    return resolved


def validate(root, plan):
    if sys.platform != "darwin":
        raise RuntimeError("Native mutation execution requires macOS")
    if (root / ".git").exists() or not root.name.startswith("vw-companion-review-"):
        raise RuntimeError("Expected an isolated vw-companion-review-* snapshot without Git metadata")
    if not any(parent == Path("/private/tmp") or parent == Path("/tmp") for parent in root.parents):
        raise RuntimeError("Snapshot must be in the task-private temporary area")
    if plan.get("finalized") is not True:
        raise RuntimeError("Mutation plan is not finalized against implementation-ready sources")
    cases = plan["mutations"]
    if not cases or len({case["name"] for case in cases}) != len(cases):
        raise RuntimeError("Missing or duplicate mutation cases")
    required = set(plan["required_guards"])
    covered = {case["guard"] for case in cases}
    if not required.issubset(covered):
        raise RuntimeError("Required guards missing from plan")
    manifest_bytes = (root / "source-manifest.json").read_bytes()
    if sha(manifest_bytes) != plan["source_manifest_sha256"]:
        raise RuntimeError("Source manifest differs from finalized reviewed plan")
    manifest = json.loads(manifest_bytes)
    for relative, expected in manifest.items():
        if sha(contained(root, relative).read_bytes()) != expected:
            raise RuntimeError("Snapshot hash mismatch: " + relative)
    for case in cases:
        if not re.fullmatch(r"[a-z0-9_]+", case["name"]):
            raise RuntimeError("Unsafe mutation name")
        if not case.get("expected_runtime_failures") or not case.get("edits") or not case.get("filter"):
            raise RuntimeError("Missing exact edits or intended XCTest witness: " + case["name"])
        for edit in case["edits"]:
            relative = edit["path"]
            if relative not in manifest or not relative.startswith("macos/Sources/"):
                raise RuntimeError("Mutation may change only manifested production Swift source")
            text = contained(root, relative).read_text()
            count = edit.get("count", 1)
            if count < 1 or not edit["before"] or text.count(edit["before"]) != count:
                raise RuntimeError("Mutation target mismatch before execution: " + case["name"])
            if edit["before"] == edit["after"]:
                raise RuntimeError("No-op mutation: " + case["name"])
    return manifest


def run_command(command, cwd, log_path, timeout):
    started = time.monotonic()
    timed_out = False
    with log_path.open("w") as output:
        process = subprocess.Popen(command, cwd=cwd, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = process.wait(timeout=timeout)
        except BaseException as error:
            timed_out = isinstance(error, subprocess.TimeoutExpired)
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
            if not timed_out:
                raise
            code = 124
    text = log_path.read_text(errors="replace")
    failures = re.findall(r"Test Case '-\[[^\]]+ (test[^\]]+)\]' failed", text)
    starts = re.findall(r"Test Case '-\[[^\]]+ (test[^\]]+)\]' started", text)
    # Crash/compiler errors are not runtime kills. A named XCTest must actually
    # start and fail an assertion, and the native build must complete.
    return {"command": command, "exit_code": code, "timed_out": timed_out,
            "seconds": round(time.monotonic() - started, 3), "log": log_path.name,
            "build_completed": "Build complete!" in text,
            "runtime_failures": sorted(set(failures)), "started_tests": sorted(set(starts))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    root = args.snapshot.resolve(strict=True)
    plan = json.loads(args.plan.read_text())
    manifest = validate(root, plan)
    report = args.report.resolve()
    if report.exists():
        raise RuntimeError("Report directory must be new; previous evidence is immutable")
    report.mkdir(parents=True)
    save(report / "plan.json", plan)
    save(report / "source-hashes.json", manifest)
    targets = {edit["path"] for case in plan["mutations"] for edit in case["edits"]}
    originals = {relative: contained(root, relative).read_bytes() for relative in targets}
    for relative, data in originals.items():
        backup = report / "source-backups" / relative
        backup.parent.mkdir(parents=True, exist_ok=True)
        backup.write_bytes(data)
    def interrupted(signum, frame):
        raise KeyboardInterrupt("Native campaign interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    results = {"status": "running", "mutations": [], "source_restored": False}

    def checkpoint():
        save(report / "results.json", results)

    def restore():
        for relative, data in originals.items():
            contained(root, relative).write_bytes(data)
        actual = {relative: sha(contained(root, relative).read_bytes()) for relative in manifest}
        save(report / "restored-source-hashes.json", actual)
        if actual != manifest:
            raise RuntimeError("Source hash mismatch after restoration; stop concurrent edits")
        results["source_restored"] = True
        checkpoint()

    def full_check(name):
        return run_command(["/bin/bash", str(root / "scripts/test-macos-companion.sh"), str(report / name)],
                           root, report / (name + ".log"), plan.get("full_timeout_seconds", 900))

    checkpoint()
    try:
        results["baseline"] = full_check("baseline")
        checkpoint()
        if results["baseline"]["exit_code"] != 0:
            raise RuntimeError("Baseline failed; no mutations were applied")
        expected_tests = {name for case in plan["mutations"] for name in case["expected_runtime_failures"]}
        missing = sorted(expected_tests - set(results["baseline"]["started_tests"]))
        if missing:
            results["missing_baseline_witnesses"] = missing
            checkpoint()
            raise RuntimeError("Baseline did not execute every intended mutation witness")
        for case in plan["mutations"]:
            restore()
            results["source_restored"] = False
            results["mutation_applied"] = True
            patches = []
            for edit in case["edits"]:
                path = contained(root, edit["path"])
                before = path.read_text()
                if before.count(edit["before"]) != edit.get("count", 1):
                    raise RuntimeError("Mutation target changed during campaign: " + case["name"])
                after = before.replace(edit["before"], edit["after"])
                patches.extend(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                                                   fromfile=edit["path"], tofile=edit["path"]))
                path.write_text(after)
            (report / (case["name"] + ".patch")).write_text("".join(patches))
            result = run_command(["/usr/bin/swift", "test", "--package-path", str(root / "macos"),
                                  "--filter", case["filter"]], root, report / (case["name"] + ".log"),
                                 plan.get("mutation_timeout_seconds", 240))
            witnessed = sorted(set(result["runtime_failures"]) & set(case["expected_runtime_failures"]))
            if result["timed_out"]:
                verdict = "timeout"
            elif result["exit_code"] == 0:
                verdict = "survived" if result["started_tests"] else "no_tests_executed"
            elif result["build_completed"] and witnessed:
                verdict = "killed_runtime"
            elif not result["build_completed"]:
                verdict = "invalid_compile_or_launch"
            else:
                verdict = "unintended_runtime_failure"
            result.update(name=case["name"], guard=case["guard"], verdict=verdict, intended_witnesses=witnessed)
            results["mutations"].append(result)
            checkpoint()
            print(json.dumps({key: result[key] for key in ["name", "guard", "verdict", "intended_witnesses", "seconds"]}), flush=True)
    except BaseException as error:
        results["campaign_error"] = type(error).__name__ + ": " + str(error)
        checkpoint()
        raise
    finally:
        restore()
        if results.get("campaign_error", "").startswith("KeyboardInterrupt"):
            results["restored_baseline"] = {"exit_code": None, "skipped": "Interrupted after source restoration; explicit rerun required"}
        elif results.get("mutation_applied"):
            results["restored_baseline"] = full_check("restored-baseline")
        else:
            results["restored_baseline"] = {"exit_code": None, "skipped": "Baseline failed before any mutation; no redundant rerun"}
        results["counts"] = {verdict: sum(row["verdict"] == verdict for row in results["mutations"])
                             for verdict in ["killed_runtime", "survived", "timeout", "no_tests_executed", "invalid_compile_or_launch", "unintended_runtime_failure"]}
        results["planned_mutations"] = len(plan["mutations"])
        results["unexecuted_mutations"] = len(plan["mutations"]) - len(results["mutations"])
        results["status"] = "passed" if ("campaign_error" not in results and results["restored_baseline"]["exit_code"] == 0
            and results["counts"]["killed_runtime"] == len(plan["mutations"])) else "incomplete_or_failed"
        checkpoint()
    return 0 if results["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
