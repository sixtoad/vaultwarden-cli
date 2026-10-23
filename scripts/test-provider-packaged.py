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
PHASES = frozenset("startup initializeCore configuration configurationNative configurationDecode configurationUnreadable configurationInvalid configurationIdentity configureCore begin nativeSend finish settle shutdown controller".split())
PROVISION_PHASES = frozenset("input openKeychain readCertificate findIdentity persistentReference saveConfiguration savedConfiguration savedIdentity savedFingerprint savedMetadata".split())
CHECKS = frozenset("none releaseMac ciEnvironment configuredLoopback fingerprint recoveryMarker pendingCoreMarker pendingNativeMarker terminalCoreMarker approvedStatus settledNativeMarker negativeClosed sessionUnlocked reviewDecidable completeArguments decisionStatus inbox terminalStatus".split())
COMMANDS = frozenset("session list unlock review decision status".split())
NATIVE_COMMANDS = frozenset("session list unlock review approve deny status".split())


def progress_diagnostics(stdout, stderr, prefix, phases):
    """Retain the most recent fixed boundaries on failure, never raw output."""
    progress = []
    for line in (stdout[-65536:] + b"\n" + stderr[-65536:]).splitlines():
        parts = line.split(b":")
        if len(parts) != 3 or parts[0] != prefix:
            continue
        phase, event = (part.decode("ascii", errors="replace") for part in parts[1:])
        if phase in phases and event in {"enter", "complete"}:
            progress.append({"phase": phase, "event": event})
            progress = progress[-32:]
    return progress


def app_diagnostics(code, stdout, stderr, timed_out=False):
    """Keep only exact, bounded test markers; discard all arbitrary app output."""
    result = {"exit_code": code, "timed_out": timed_out, "failures": [], "native_rejections": []}
    for line in (stdout[-65536:] + b"\n" + stderr[-65536:]).splitlines():
        parts = line.split(b":")
        if len(parts) == 3 and parts[0] == b"COMPANION_PROVIDER_TLS_FAILED":
            phase, check = (part.decode("ascii", errors="replace") for part in parts[1:])
            if phase in PHASES and check in CHECKS and len(result["failures"]) < 16:
                result["failures"].append({"phase": phase, "check": check})
        if len(parts) == 2 and parts[0] == b"COMPANION_PROVIDER_TLS_NATIVE_REJECTED":
            command = parts[1].decode("ascii", errors="replace")
            if command in NATIVE_COMMANDS and len(result["native_rejections"]) < 16:
                result["native_rejections"].append(command)
    result["passed"] = (code == 0 and not timed_out
                        and stdout.splitlines().count(b"COMPANION_PROVIDER_TLS_OK") == 1
                        and not result["failures"])
    if not result["passed"]:
        result["progress"] = progress_diagnostics(stdout, stderr, b"COMPANION_PROVIDER_TLS_PROGRESS", PHASES)
    return result


def provision_diagnostics(code, stdout, stderr, timed_out=False):
    result = {"exit_code": code, "timed_out": timed_out, "failures": []}
    for line in (stdout[-65536:] + b"\n" + stderr[-65536:]).splitlines():
        parts = line.split(b":")
        if len(parts) == 2 and parts[0] == b"COMPANION_PROVIDER_PROVISION_FAILED":
            phase = parts[1].decode("ascii", errors="replace")
            if phase in PROVISION_PHASES and len(result["failures"]) < 16:
                result["failures"].append(phase)
    result["passed"] = (code == 0 and not timed_out
                        and stdout.splitlines().count(b"COMPANION_PROVIDER_PROVISION_OK") == 1
                        and not result["failures"])
    if not result["passed"]:
        result["progress"] = progress_diagnostics(stdout, stderr, b"COMPANION_PROVIDER_PROVISION_PROGRESS", PROVISION_PHASES)
    return result


def run_diagnosed(argv, diagnostics, **options):
    try:
        result = run(argv, **options)
        return diagnostics(result.returncode, result.stdout, result.stderr)
    except subprocess.CalledProcessError as error:
        return diagnostics(error.returncode, error.stdout or b"", error.stderr or b"")
    except subprocess.TimeoutExpired as error:
        return diagnostics(None, error.stdout or b"", error.stderr or b"", timed_out=True)


def launch_app(executable, environment):
    return run_diagnosed([executable], app_diagnostics, env=environment)


def command_counts(path):
    # A command name is the fixture's only recorded field; still allowlist it.
    result = dict.fromkeys(sorted(COMMANDS), 0)
    if not path.is_file():
        return result
    with path.open("rb") as source:
        content = source.read(16385)
    if len(content) > 16384:
        raise RuntimeError("fixture command evidence exceeds bound")
    try:
        for line in content.splitlines():
            command = json.loads(line)["command"]
            if command not in COMMANDS:
                raise ValueError()
            result[command] += 1
    except (ValueError, TypeError, KeyError):
        raise RuntimeError("fixture command evidence invalid") from None
    return result


def run(argv, **kwargs):
    return subprocess.run(list(map(str, argv)), check=True, timeout=45,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)


def search_list():
    return shlex.split(run(["security", "list-keychains", "-d", "user"]).stdout.decode())


def keychain_directory(container):
    # The app's sandbox may not read the external helper's system temp directory.
    # Keep only this disposable file-based Keychain inside its own container;
    # neither the app entitlement nor the exact-executable Keychain ACL changes.
    if container.is_symlink() or not container.is_dir():
        raise RuntimeError("Missing or redirected app sandbox container.")
    return Path(tempfile.mkdtemp(prefix="provider-fixture-keychain-", dir=container))


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
    if container.is_symlink() or not container.is_dir():
        raise SystemExit("Run the ordinary packaged smoke first to create the isolated app sandbox.")
    args.evidence.mkdir(parents=True, exist_ok=True)
    original_search = search_list()
    temporary = Path(tempfile.mkdtemp(prefix="flutter-provider-packaged-"))
    keychain_temporary = None
    keychain = None
    helper = temporary / "identity-helper"
    created_keychain = False
    created_configuration = False
    server = None
    report = {"kind": "packaged-aot-real-tls-synthetic-backend", "cases": {}, "cleanup_passed": False}
    try:
        keychain_temporary = keychain_directory(container)
        keychain = keychain_temporary / "fixture.keychain-db"
        run([sys.executable, FIXTURE, "provision", temporary])
        run(["swiftc", "-parse-as-library", ROOT / "macos/Sources/CompanionCore/Protocol.swift",
             ROOT / "macos/Sources/CompanionCore/Trust.swift",
             ROOT / "companion/macos/Runner/ProviderSettings.swift",
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
            result = launch_app(executable, env)
            report["cases"][name]["launches"].append(result)
            report["cases"][name]["observed_command_counts"] = command_counts(temporary / "requests.jsonl")
            if not result["passed"]:
                raise RuntimeError("packaged application failed; see sanitized packaged-tls.json")

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
            ("controller-unlock", "controller", "client", "ca", "controller-unlock", ["session", "unlock", "session", "list", "review", "decision", "status", "status"]),
            ("controller-recovery", "drop", "client", "ca", "drop", ["session", "review", "decision", "status"]),
            ("controller-pending", "drop-pending", "client", "ca", "drop", ["session", "review", "decision", "status"]),
        ]
        for name, mode, client, ca, scenario, expected_commands in cases:
            report["cases"][name] = {"passed": False, "launches": [],
                                     "expected_command_counts": {command: expected_commands.count(command) for command in sorted(COMMANDS)}}
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
            provision = run_diagnosed(
                [helper, temporary, configuration, client, ca, f"https://127.0.0.1:{port}", pin, keychain],
                provision_diagnostics)
            report["cases"][name]["provision"] = provision
            report["cases"][name]["observed_command_counts"] = command_counts(temporary / "requests.jsonl")
            if not provision["passed"]:
                raise RuntimeError("fixture provisioning failed; see sanitized packaged-tls.json")
            launch(scenario, client)
            if mode in ["drop", "drop-pending"]:
                # A separate AOT process reads the native durable marker and sends
                # only status. Count bodies across both processes to catch replay.
                recovery = "recover-pending" if mode == "drop-pending" else "recover"
                launch("controller-" + recovery if name.startswith("controller-") else recovery, client)
            commands = [json.loads(line)["command"] for line in (temporary / "requests.jsonl").read_text().splitlines()]
            if commands != expected_commands:
                raise RuntimeError(f"{name}: wrong command count/order")
            report["cases"][name].update(passed=True, commands=commands)
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
        if keychain_temporary is not None:
            try:
                # Only the fresh 0700 fixture directory, never the app container.
                shutil.rmtree(keychain_temporary)
            except Exception:
                cleanup_errors.append("fixture Keychain directory removal")
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
