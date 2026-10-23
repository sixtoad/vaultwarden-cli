#!/usr/bin/env python3
"""Verify IconServices on disposable Intel macOS 26 GitHub runners.

Work around actions/runner-images#14751 only after reproducing its timeout.
Keep all app/transport tests unchanged; never run on an operator's Mac.
"""
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SERVICE = "com.apple.iconservices.iconservicesagent"


def command(argv, timeout=10):
    try:
        return subprocess.run(list(map(str, argv)), timeout=timeout,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.TimeoutExpired:
        return None
    except OSError:
        return subprocess.CompletedProcess([], 127, stdout=b"", stderr=b"")


def outcome(result):
    return {"timed_out": result is None,
            "exit_code": None if result is None else result.returncode}


def machine_metadata():
    version = os.environ.get("ImageVersion", "")
    os_version = platform.mac_ver()[0]
    build = command(["/usr/bin/sw_vers", "-buildVersion"])
    build_text = build.stdout.decode("ascii", errors="replace").strip() if build is not None else ""
    return {"image_os": "macos26", "architecture": "x86_64",
            "image_version": version if re.fullmatch(r"\d{8}\.\d{4}\.\d{1,4}", version) else "unknown",
            "os_version": os_version if re.fullmatch(r"\d{1,2}\.\d{1,2}(\.\d{1,2})?", os_version) else "unknown",
            "os_build": build_text if re.fullmatch(r"\d{1,2}[A-Z]\d{1,5}[a-z]?", build_text) else "unknown"}


def probe(executable):
    result = command([executable])
    if result is None:
        return "timed_out"
    if result.returncode == 0 and result.stdout.splitlines() == [b"COMPANION_ICON_PROBE_OK"]:
        return "passed"
    return "failed"


def prepare(executable, report):
    report["stage"] = "initial_probe"
    report["before"] = probe(executable)
    if report["before"] == "passed":
        report["passed"] = True
        report["stage"] = "complete"
        return
    if report["before"] != "timed_out":
        raise RuntimeError("IconServices probe failed without the known timeout")
    domain = f"gui/{os.getuid()}"
    target = f"{domain}/{SERVICE}"
    report["stage"] = "disable_service"
    disabled = command(["/bin/launchctl", "disable", target])
    report["disable"] = outcome(disabled)
    if disabled is None or disabled.returncode != 0:
        raise RuntimeError("Could not disable the broken CI icon service")
    report["workaround_applied"] = True
    # A crash-looping service may already be absent and bootout can return an
    # error. Verify the postconditions instead of accepting arbitrary failures.
    report["stage"] = "unload_service"
    report["bootout"] = outcome(command(["/bin/launchctl", "bootout", target]))
    loaded = command(["/bin/launchctl", "print", target])
    state = command(["/bin/launchctl", "print-disabled", domain])
    report["inspect_service"] = outcome(loaded)
    report["inspect_disabled"] = outcome(state)
    report["service_unloaded"] = (loaded is not None and loaded.returncode == 113 and
        f'Could not find service "{SERVICE}"'.encode() in loaded.stderr)
    report["service_disabled"] = (state is not None and state.returncode == 0 and
        re.search(rb'"com\.apple\.iconservices\.iconservicesagent"\s*=>\s*true', state.stdout) is not None)
    if not report["service_unloaded"] or not report["service_disabled"]:
        raise RuntimeError("CI icon service postconditions failed")
    report["stage"] = "final_probe"
    report["after"] = probe(executable)
    report["passed"] = report["after"] == "passed"
    if not report["passed"]:
        raise RuntimeError("IconServices remains unavailable after the CI workaround")
    report["stage"] = "complete"


def main():
    if (sys.platform != "darwin" or platform.machine() != "x86_64" or
            os.environ.get("GITHUB_ACTIONS") != "true" or
            os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted" or
            os.environ.get("ImageOS") != "macos26"):
        raise SystemExit("Requires a disposable GitHub-hosted Intel macOS 26 runner")
    if len(sys.argv) != 2:
        raise SystemExit("Expected evidence directory")
    evidence = Path(sys.argv[1])
    evidence.mkdir(parents=True, exist_ok=True)
    report = {"kind": "macos-intel-iconservices-preflight", "passed": False,
              "workaround_applied": False, "machine": machine_metadata(), "stage": "compile"}
    try:
        with tempfile.TemporaryDirectory(prefix="companion-icon-probe-") as temporary:
            executable = Path(temporary) / "icon-probe"
            built = command(["/usr/bin/swiftc", ROOT / "companion/fixtures/macos_icon_probe.swift",
                             "-o", executable], timeout=60)
            report["compile"] = outcome(built)
            if built is None or built.returncode != 0:
                raise RuntimeError("Could not build the CI IconServices probe")
            prepare(executable, report)
    finally:
        (evidence / "macos-gui-preflight.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
