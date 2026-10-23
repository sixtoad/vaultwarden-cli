#!/usr/bin/env python3
"""CI-only real pilot channel import, persisted metadata and foreground admission.

Reuses the packaged TLS fixture and closed diagnostics. No production test hooks;
the disposable bundle is passed over stdin, never environment/argv or evidence.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import selectors
import shlex
import shutil
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("packaged", Path(__file__).with_name("test-provider-packaged.py"))
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


def wait_marker(process, marker, seconds=15):
    deadline = time.monotonic() + seconds
    output = b""
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while time.monotonic() < deadline:
            if not selector.select(max(0, deadline - time.monotonic())):
                break
            chunk = os.read(process.stdout.fileno(), 4096)
            if not chunk:
                break
            output += chunk
            if len(output) > 65536:
                break
            if marker in output.splitlines():
                return
    raise RuntimeError("fixture readiness failed")


def default_keychain():
    paths = shlex.split(PROBE.run(["security", "default-keychain", "-d", "user"]).stdout.decode())
    if len(paths) != 1:
        raise RuntimeError("default Keychain unavailable")
    return paths[0]


def verify_saved(path, bundle):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 131072:
        raise RuntimeError("persisted fixture configuration invalid")
    raw = path.read_bytes()
    value = json.loads(raw)
    saved = value["configuration"]
    if (saved["endpoint"] != bundle["endpoint"] or saved["leafSHA256"] != bundle["leaf_sha256"]
            or saved["trustedCA"] != bundle["ca_der"] or value.get("pendingID") is not None
            or not base64.b64decode(saved["identityReference"], validate=True)):
        raise RuntimeError("persisted fixture metadata mismatch")
    return raw


def verify_commands(path):
    expected = dict.fromkeys(sorted(PROBE.COMMANDS), 0)
    expected.update(unlock=1, session=1, list=1)
    if PROBE.command_counts(path) != expected:
        raise RuntimeError("pilot fixture command count mismatch")
    commands = [json.loads(line)["command"] for line in path.read_text().splitlines()]
    if commands != ["unlock", "session", "list"]:
        raise RuntimeError("pilot fixture command order mismatch")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("app", type=Path)
    parser.add_argument("evidence", type=Path)
    args = parser.parse_args()
    if sys.platform != "darwin" or os.environ.get("CI") != "true":
        raise SystemExit("Pilot channel provisioning requires a disposable macOS CI runner.")
    executable = args.app.resolve() / "Contents/MacOS/companion_slice"
    if not executable.is_file():
        raise SystemExit("Missing pilot fixture executable.")
    container = Path.home() / "Library/Containers/dev.vaultwarden.companionSlice/Data"
    directories = [container / "Library/Application Support/dev.vaultwarden.companionSlice.provider",
                   Path.home() / "Library/Application Support/dev.vaultwarden.companionSlice.provider"]
    if any(path.exists() or path.is_symlink() for path in directories) or container.is_symlink():
        raise SystemExit("Refusing pre-existing or redirected provider state.")
    args.evidence.mkdir(parents=True, exist_ok=True)
    original_default, original_search = default_keychain(), PROBE.search_list()
    temporary = Path(tempfile.mkdtemp(prefix="pilot-channel-ci-"))
    keychain_directory = keychain = None
    app = focus = server = None
    keychain_created = False
    configuration_owned = False
    report = {"kind": "packaged-pilot-production-channel", "cases": {}, "passed": False, "cleanup_passed": False}
    try:
        PROBE.run([sys.executable, PROBE.FIXTURE, "provision", temporary])
        helper = temporary / "focus-helper"
        PROBE.run(["swiftc", "-parse-as-library", PROBE.ROOT / "companion/provider_native_tests/PilotFixtureFocus.swift", "-o", helper])
        server = subprocess.Popen([sys.executable, str(PROBE.FIXTURE), "serve", str(temporary), "--mode", "controller"],
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        with selectors.DefaultSelector() as selector:
            selector.register(server.stdout, selectors.EVENT_READ)
            if not selector.select(timeout=15):
                raise RuntimeError("fixture server readiness failed")
            port = int(server.stdout.readline(32))
        if not 0 < port <= 65535:
            raise RuntimeError("fixture endpoint invalid")
        bundle = {"version": 1, "kind": "disposable-companion-pilot",
                  "endpoint": f"https://127.0.0.1:{port}/v1/companion",
                  "leaf_sha256": hashlib.sha256((temporary / "server.der").read_bytes()).hexdigest(),
                  "client_sha256": hashlib.sha256((temporary / "client.der").read_bytes()).hexdigest(),
                  "ca_der": base64.b64encode((temporary / "ca.der").read_bytes()).decode(),
                  "pkcs12": base64.b64encode((temporary / "client.p12").read_bytes()).decode(),
                  "import_passphrase": "synthetic-only", "unlock_password": "synthetic-only"}
        saved_bytes = None
        configuration = None
        for scenario in ["foreground", "inactive"]:
            environment = dict(os.environ, COMPANION_PILOT_CASE=scenario)
            app = subprocess.Popen([str(executable)], env=environment, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            wait_marker(app, b"COMPANION_PILOT_READY")
            if scenario == "foreground":
                # The app launch has now established its sandbox container.
                keychain_directory = PROBE.keychain_directory(container)
                keychain = keychain_directory / "fixture.keychain-db"
                PROBE.run(["security", "create-keychain", "-p", "synthetic-fixture-only", keychain])
                keychain_created = True
                PROBE.run(["security", "unlock-keychain", "-p", "synthetic-fixture-only", keychain])
                PROBE.run(["security", "list-keychains", "-d", "user", "-s", *original_search, keychain])
                PROBE.run(["security", "default-keychain", "-d", "user", "-s", keychain])
                if default_keychain() != str(keychain):
                    raise RuntimeError("disposable default Keychain not selected")
            focus = subprocess.Popen([str(helper), str(app.pid), scenario], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            wait_marker(focus, b"COMPANION_PILOT_FOCUS_READY")
            # A changed valid pin would replace persisted metadata if the native
            # inactive gate were bypassed. It must not import or save anything.
            payload = dict(bundle, **({"leaf_sha256": "0" * 64} if scenario == "inactive" else {}))
            configuration_owned = True
            try:
                stdout, stderr = app.communicate(json.dumps(payload).encode(), timeout=45)
                result = PROBE.app_diagnostics(app.returncode, stdout, stderr)
            except subprocess.TimeoutExpired:
                PROBE.stop(app)
                stdout, stderr = app.communicate(timeout=5)
                result = PROBE.app_diagnostics(app.returncode, stdout, stderr, timed_out=True)
            report["cases"][scenario] = result
            PROBE.stop(app)
            PROBE.stop(focus)
            app = focus = None
            if not result["passed"]:
                raise RuntimeError("packaged pilot case failed")
            paths = [directory / "configuration-v1.json" for directory in directories
                     if (directory / "configuration-v1.json").is_file()]
            if len(paths) != 1:
                raise RuntimeError("persisted fixture configuration unavailable")
            configuration = paths[0]
            observed = verify_saved(configuration, bundle)
            if scenario == "foreground":
                saved_bytes = observed
            elif observed != saved_bytes or list(configuration.parent.glob("configuration-before-pilot-*")):
                raise RuntimeError("inactive setup changed persisted configuration")
            verify_commands(temporary / "requests.jsonl")
        report.update(passed=True, observed_command_counts=PROBE.command_counts(temporary / "requests.jsonl"))
    finally:
        cleanup_errors = []
        for label, process in [("app", app), ("focus", focus), ("server", server)]:
            try:
                PROBE.stop(process)
            except Exception:
                cleanup_errors.append(f"{label} stop")
        # Never restore/delete a Keychain while the exact app may still use it.
        app_stopped = app is None or app.poll() is not None
        restored = False
        if app_stopped:
            try:
                PROBE.run(["security", "default-keychain", "-d", "user", "-s", original_default])
                PROBE.run(["security", "list-keychains", "-d", "user", "-s", *original_search])
                restored = default_keychain() == original_default and PROBE.search_list() == original_search
                if not restored:
                    cleanup_errors.append("Keychain restoration mismatch")
            except Exception:
                cleanup_errors.append("Keychain restoration failed")
        else:
            cleanup_errors.append("app termination uncertain; fixture retained")
        # Restore user settings once the app is stopped, but retain owned files
        # if any process-stop check failed, even when Keychain restoration worked.
        if restored and not cleanup_errors:
            try:
                if keychain_created:
                    PROBE.run(["security", "delete-keychain", keychain])
                if keychain_directory is not None:
                    shutil.rmtree(keychain_directory)
                if configuration_owned:
                    for directory in directories:
                        if directory.is_symlink():
                            raise RuntimeError("fixture configuration redirected")
                        if directory.exists():
                            # Both exact directories were absent before this run.
                            shutil.rmtree(directory)
                shutil.rmtree(temporary)
            except Exception:
                cleanup_errors.append("fixture removal failed")
        report["cleanup_passed"] = restored and not cleanup_errors
        report["cleanup_errors"] = cleanup_errors
        (args.evidence / "pilot-channel.json").write_text(json.dumps(report, indent=2) + "\n")
        if not report["cleanup_passed"]:
            raise RuntimeError("pilot fixture cleanup failed; owned material retained if uncertain")
    print("Packaged pilot native channel, single unlock and inactive rejection passed.")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Subprocess errors can retain private output: never print an exception.
        raise SystemExit("Pilot packaged verification failed; inspect sanitized pilot-channel.json.") from None
