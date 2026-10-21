#!/usr/bin/env python3
"""Run real TLS through the AOT Flutter -> FRB -> native adapter in fresh Mac CI.

No production test hooks. Provision only disposable synthetic identity/config;
refuse existing development configuration, restore the original Keychain search
list, and remove only fixture-created configuration/keychain/temp files.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import shlex
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "companion/fixtures/provider_tls.py"


def run(argv, **kwargs):
    return subprocess.run(list(map(str, argv)), check=True, timeout=45,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)


def search_list():
    return shlex.split(run(["security", "list-keychains", "-d", "user"]).stdout.decode())


def stop(process):
    if process is None:
        return
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
            raise RuntimeError("fixture ignored termination")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("app", type=Path)
    parser.add_argument("evidence", type=Path)
    args = parser.parse_args()
    if sys.platform != "darwin" or os.environ.get("CI") != "true":
        raise SystemExit("Packaged TLS provisioning requires a disposable macOS CI runner.")
    executable = args.app.resolve() / "Contents/MacOS/companion_slice"
    if not executable.is_file():
        raise SystemExit("Missing packaged fixture executable.")
    # Bundle ID is deliberately distinct from the installed Swift companion.
    container = Path.home() / "Library/Containers/dev.vaultwarden.companionSlice/Data"
    configuration = container / "Library/Application Support/dev.vaultwarden.companionSlice.provider/configuration-v1.json"
    if configuration.exists() or configuration.is_symlink():
        raise SystemExit("Refusing to replace existing development provider configuration.")
    if not container.is_dir():
        raise SystemExit("Run the ordinary packaged smoke first to create the isolated app sandbox.")
    args.evidence.mkdir(parents=True, exist_ok=True)
    original_search = search_list()
    temporary = Path(tempfile.mkdtemp(prefix="flutter-provider-packaged-"))
    keychain = temporary / "fixture.keychain-db"
    helper = temporary / "identity-helper"
    created_keychain = False
    created_configuration = False
    server = None
    report = {"kind": "packaged-aot-real-tls-synthetic-backend", "cases": {}, "cleanup_passed": False}
    try:
        run([sys.executable, FIXTURE, "provision", temporary])
        run(["swiftc", "-parse-as-library", ROOT / "macos/Sources/CompanionCore/Protocol.swift",
             ROOT / "macos/Sources/CompanionCore/Trust.swift",
             ROOT / "companion/provider_native_tests/ProviderFixtureIdentity.swift", "-o", helper])
        run(["security", "create-keychain", "-p", "synthetic-fixture-only", keychain])
        created_keychain = True
        run(["security", "unlock-keychain", "-p", "synthetic-fixture-only", keychain])
        run(["security", "list-keychains", "-d", "user", "-s", *original_search, keychain])
        for name in ["client", "foreign", "revoked"]:
            # Allow exactly this built application to use the disposable key.
            # Never import into the login/default/installed-app keychain.
            run(["security", "import", temporary / f"{name}.p12", "-k", keychain,
                 "-P", "synthetic-only", "-T", executable])

        def launch(scenario, client):
            env = dict(os.environ, COMPANION_PROVIDER_CASE=scenario,
                       COMPANION_EXPECT_CLIENT_SHA256=hashlib.sha256((temporary / f"{client}.der").read_bytes()).hexdigest())
            result = run([executable], env=env)
            if result.stdout.count(b"COMPANION_PROVIDER_TLS_OK") != 1:
                raise RuntimeError("packaged application did not report verified completion")

        cases = [
            ("approve", "normal", "client", "ca", "approve", ["session", "review", "decision"]),
            ("deny", "normal", "client", "ca", "deny", ["session", "review", "decision"]),
            ("wrong-password", "authentication422", "client", "ca", "wrong-password", ["session", "review", "decision"]),
            ("pin", "normal", "client", "ca", "negative", []),
            ("ca", "normal", "client", "other-ca", "negative", []),
            ("foreign-client", "normal", "foreign", "ca", "negative", []),
            ("unenrolled-client", "normal", "revoked", "ca", "negative", ["session"]),
            ("hostname", "wrong-host", "client", "ca", "negative", []),
            ("expired", "expired", "client", "ca", "negative", []),
            ("redirect", "redirect", "client", "ca", "negative", ["session"]),
            ("oversized", "oversized", "client", "ca", "negative", ["session"]),
            ("schema", "invalid-schema", "client", "ca", "negative", ["session"]),
            ("lost-response-relaunch", "drop", "client", "ca", "drop", ["session", "review", "decision", "status"]),
            ("pending-relaunch", "drop-pending", "client", "ca", "drop", ["session", "review", "decision", "status"]),
        ]
        for name, mode, client, ca, scenario, expected_commands in cases:
            server = subprocess.Popen([sys.executable, str(FIXTURE), "serve", str(temporary), "--mode", mode],
                                      stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            with selectors.DefaultSelector() as selector:
                selector.register(server.stdout, selectors.EVENT_READ)
                if not selector.select(timeout=15):
                    raise RuntimeError("fixture startup deadline")
                port = int(server.stdout.readline().strip())
            leaf = mode if mode in ["wrong-host", "expired"] else "server"
            pin = "0" * 64 if name == "pin" else hashlib.sha256((temporary / f"{leaf}.der").read_bytes()).hexdigest()
            created_configuration = True
            run([helper, temporary, configuration, client, ca, f"https://127.0.0.1:{port}", pin, keychain])
            launch(scenario, client)
            if mode in ["drop", "drop-pending"]:
                # A separate AOT process reads the native durable marker and sends
                # only status. Count bodies across both processes to catch replay.
                launch("recover-pending" if mode == "drop-pending" else "recover", client)
            commands = [json.loads(line)["command"] for line in (temporary / "requests.jsonl").read_text().splitlines()]
            if commands != expected_commands:
                raise RuntimeError(f"{name}: wrong command count/order")
            report["cases"][name] = {"passed": True, "commands": commands}
            stop(server)
            server = None
            configuration.unlink()
        report["passed"] = True
    finally:
        cleanup_errors = []
        try:
            stop(server)
        except Exception:
            cleanup_errors.append("fixture stop")
        if created_configuration:
            configuration.unlink(missing_ok=True)
        try:
            run(["security", "list-keychains", "-d", "user", "-s", *original_search])
            if search_list() != original_search:
                cleanup_errors.append("Keychain search list mismatch")
        except Exception:
            cleanup_errors.append("Keychain search list restore")
        if created_keychain:
            try:
                run(["security", "delete-keychain", keychain])
            except Exception:
                cleanup_errors.append("fixture Keychain removal")
        # temporary was allocated by this process; it contains only fixture files.
        shutil.rmtree(temporary)
        report["cleanup_passed"] = not cleanup_errors
        report["cleanup_errors"] = cleanup_errors
        (args.evidence / "packaged-tls.json").write_text(json.dumps(report, indent=2) + "\n")
        if cleanup_errors:
            raise RuntimeError("packaged fixture cleanup failed")
    print("Packaged AOT provider TLS cases and exact single-send recovery passed.")


if __name__ == "__main__":
    main()
