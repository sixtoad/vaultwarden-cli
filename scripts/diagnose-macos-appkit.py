#!/usr/bin/env python3
"""Characterize native GUI startup on a disposable runner, without Flutter/vaults."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import plistlib
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def collect(executable, variant, run_app, report):
    launches = report["variants"][variant] = []
    for index in range(20):
        attempt = {"index": index + 1, "observation": "incomplete"}
        launches.append(attempt)
        try:
            result = run_app([executable, variant], dict(os.environ), timeout=8,
                             sample_after=3, include_progress=True)
        except (OSError, subprocess.SubprocessError, RuntimeError) as error:
            attempt["harness_failure"] = ("os_error" if isinstance(error, OSError) else
                "process_error" if isinstance(error, subprocess.SubprocessError) else "instrumentation_error")
            raise RuntimeError("Native startup diagnostic harness failed") from None
        attempt.update(result, observation="complete")
        expected = [{"phase": "startup", "event": "enter"},
                    {"phase": "startup", "event": "complete"},
                    {"phase": "shutdown", "event": "enter"}]
        if variant == "graceful":
            expected.append({"phase": "shutdown", "event": "complete"})
        attempt["termination_markers_match"] = result.get("progress") == expected
        attempt["passed"] = result["passed"] and attempt["termination_markers_match"]
        if not attempt["passed"]:
            break


def main():
    if (sys.platform != "darwin" or platform.machine() != "x86_64" or
            os.environ.get("GITHUB_ACTIONS") != "true" or
            os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted" or
            os.environ.get("ImageOS") != "macos26"):
        raise SystemExit("Requires a disposable hosted Intel macOS 26 runner")
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    parser.add_argument("variant", choices=["abrupt", "graceful"])
    args = parser.parse_args()
    evidence = args.evidence
    evidence.mkdir(parents=True, exist_ok=True)
    gui = module("gui", "prepare-macos-gui.py")
    packaged = module("packaged", "test-provider-packaged.py")
    report = {"kind": "native-appkit-startup-characterization", "machine": gui.machine_metadata(),
              "stage": "compile", "variants": {}}
    try:
        with tempfile.TemporaryDirectory(prefix="appkit-startup-probe-") as temporary:
            bundle = Path(temporary) / "StartupProbe.app"
            executable = bundle / "Contents/MacOS/StartupProbe"
            executable.parent.mkdir(parents=True)
            (bundle / "Contents/Info.plist").write_bytes(plistlib.dumps({
                "CFBundleIdentifier": "dev.vaultwarden.disposableAppKitProbe",
                "CFBundleExecutable": "StartupProbe", "CFBundlePackageType": "APPL",
                "CFBundleName": "StartupProbe", "CFBundleVersion": "1",
                "CFBundleShortVersionString": "1.0", "NSPrincipalClass": "NSApplication",
                "NSHighResolutionCapable": True}))
            built = gui.command(["/usr/bin/swiftc", "-swift-version", "5", "-parse-as-library",
                                 ROOT / "companion/fixtures/macos_appkit_probe.swift", "-o", executable], timeout=60)
            report["compile"] = gui.outcome(built)
            if built is None or built.returncode != 0:
                raise RuntimeError("Could not compile native startup probe")
            report["stage"] = "sign"
            signed = gui.command(["/usr/bin/codesign", "--force", "--sign", "-", "--entitlements",
                                  ROOT / "companion/macos/Runner/Release.entitlements", bundle])
            report["sign"] = gui.outcome(signed)
            if signed is None or signed.returncode != 0:
                raise RuntimeError("Could not sign native startup probe")
            report["stage"] = "launch"
            collect(executable, args.variant, packaged.run_app, report)
            # This is a characterization report, not an acceptance gate. The
            # unchanged full packaged suite remains required in its own job.
            report["stage"] = "complete"
    finally:
        (evidence / "appkit-startup.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    try:
        main()
    except (OSError, subprocess.SubprocessError, RuntimeError):
        raise SystemExit("Native startup diagnostic failed; see appkit-startup.json") from None
