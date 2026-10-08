#!/usr/bin/env python3
"""Exercise production CompanionCore from an actual .app on synthetic loopback.

No installed bundle/preferences/system trust changes. --evaluate-proposal only
changes a disposable probe bundle and is not a production policy installation.
"""
import argparse
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import plistlib
import shutil
import socket
import ssl
import subprocess
import tempfile
import sys
import uuid

ROOT = Path(__file__).resolve().parents[3]
FIXTURES = ROOT / "macos/Tests/Fixtures"


@contextmanager
def isolated_probe_workspace(report):
    with tempfile.TemporaryDirectory(prefix="companion-bundle-tls-") as temporary:
        work = Path(temporary)
        try:
            yield work
        finally:
            registrations = []
            for bundle in work.glob("*.app"):
                info = bundle / "Contents/Info.plist"
                if not info.exists():
                    continue
                identifier = plistlib.loads(info.read_bytes()).get("CFBundleIdentifier", "")
                if not identifier.startswith("dev.vaultwarden.CompanionTLSProbe."):
                    continue
                registry = "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
                removed = subprocess.run([registry, "-u", str(bundle)], capture_output=True, text=True)
                remaining = subprocess.run([registry, "-dump"], capture_output=True, text=True)
                # An unregistered strict-ATS probe can return 1. Accept that
                # only when a successful read proves both its unique identity
                # and exact bundle path are absent, not on an unknown error.
                absent = remaining.returncode == 0 and identifier not in remaining.stdout and str(bundle) not in remaining.stdout
                registrations.append({"identifier": identifier, "exit_code": removed.returncode, "absence_verified": absent})
            (report / "probe-registration-cleanup.json").write_text(json.dumps(registrations, indent=2) + "\n")
            assert all(item["exit_code"] in [0, 1] and item["absence_verified"] for item in registrations), "Probe registration cleanup failed"


def run(report, strict_only=False, evaluate_proposal=False, selected_cases=None):
    report.mkdir(parents=True, exist_ok=True)
    records = []
    with isolated_probe_workspace(report) as work:
        certificates = work / "certificates"
        subprocess.run([sys.executable, str(FIXTURES / "tls_fixture.py"), "provision", str(certificates)], check=True)
        sources = sorted((ROOT / "macos/Sources/CompanionCore").glob("*.swift"))
        with (report / "build.log").open("w") as output:
            subprocess.run(["swiftc", "-swift-version", "5", "-parse-as-library", *map(str, sources), str(FIXTURES / "BundleProbe.swift"), "-o", str(work / "ApprovalCompanion")], check=True, stdout=output, stderr=subprocess.STDOUT)
        script = (ROOT / "scripts/build-macos-companion.sh").read_text()
        production_plist = script.split("<<'PLIST'\n", 1)[1].split("\nPLIST\n", 1)[0].encode() + b"\n"
        policy = plistlib.loads(production_plist)
        if evaluate_proposal:
            policy["NSAppTransportSecurity"] = {"NSAllowsArbitraryLoads": True}
            configured_plist = plistlib.dumps(policy)
        else:
            configured_plist = production_plist
            if not strict_only:
                assert policy.get("NSAppTransportSecurity") == {"NSAllowsArbitraryLoads": True}, "Production private-CA policy has not been applied"
        bundles = {}
        probe_id = "dev.vaultwarden.CompanionTLSProbe." + uuid.uuid4().hex
        for name in ["strict", "configured"]:
            bundle = work / f"{name}.app"
            (bundle / "Contents/MacOS").mkdir(parents=True)
            shutil.copy2(work / "ApprovalCompanion", bundle / "Contents/MacOS/ApprovalCompanion")
            # Isolate LaunchServices registrations from the actual app. The ATS
            # dictionary is byte-for-byte equivalent after plist decoding.
            bundle_policy = plistlib.loads(configured_plist)
            bundle_policy["CFBundleIdentifier"] = probe_id + "." + name
            bundle_policy["CFBundleName"] = "Companion TLS Probe"
            if name == "strict":
                bundle_policy.pop("NSAppTransportSecurity", None)
            else:
                assert bundle_policy["NSAppTransportSecurity"] == policy["NSAppTransportSecurity"]
            (bundle / "Contents/Info.plist").write_bytes(plistlib.dumps(bundle_policy))
            subprocess.run(["codesign", "--force", "--sign", "-", str(bundle)], check=True, capture_output=True)
            bundles[name] = bundle / "Contents/MacOS/ApprovalCompanion"
        cases = [
            ("strict_ats_private_ca_rejected", "strict", "normal", "valid", False, []),
            ("configured_private_ca_accepted", "configured", "normal", "valid", True, ["session"]),
            ("wrong_ca_rejected", "configured", "normal", "ca", False, []),
            ("wrong_pin_rejected", "configured", "normal", "pin", False, []),
            ("wrong_hostname_rejected", "configured", "wrong-host", "valid", False, []),
            ("expired_leaf_rejected", "configured", "expired", "valid", False, []),
            ("foreign_client_rejected", "configured", "normal", "foreign", False, []),
            ("revoked_client_rejected", "configured", "normal", "revoked", False, ["session"]),
            ("http_configuration_rejected", "configured", "normal", "http", False, []),
            ("tls11_rejected", "configured", "tls11", "valid", False, []),
            ("redirect_rejected", "configured", "redirect", "valid", False, ["session"]),
            ("oversized_response_rejected", "configured", "oversized", "valid", False, ["session"]),
            ("wrong_password_explicitly_rejected", "configured", "authentication422", "valid", False, ["decision"]),
            ("wrong_unlock_explicitly_rejected", "configured", "authentication-unlock422", "valid", False, ["unlock"]),
            ("lost_decision_not_retried", "configured", "drop", "valid", True, ["decision", "status"]),
            ("success_body_under_503_rejected", "configured", "success503", "valid", False, ["session"]),
            ("error_body_under_200_rejected", "configured", "error200", "valid", False, ["session"]),
            ("error_code_status_mismatch_rejected", "configured", "mismatched-error422", "valid", False, ["session"]),
            ("unknown_error_code_rejected", "configured", "unknown-error422", "valid", False, ["session"]),
            ("extra_error_field_rejected", "configured", "extra-error422", "valid", False, ["session"]),
        ]
        if strict_only:
            cases = cases[:1]
        if selected_cases:
            unknown = set(selected_cases) - {case[0] for case in cases}
            assert not unknown, f"Unknown or excluded cases: {sorted(unknown)}"
            cases = [case for case in cases if case[0] in selected_cases]
        for name, bundle, mode, variant, expected, commands in cases:
            server_log = (report / f"{name}.server.log").open("w")
            server = subprocess.Popen([sys.executable, str(FIXTURES / "tls_fixture.py"), "serve", str(certificates), "--mode", mode], stdout=subprocess.PIPE, stderr=server_log, text=True)
            try:
                port = int(server.stdout.readline())
                legacy_fixture_protocol = None
                if mode == "tls11":
                    # Independently prove the legacy server really negotiates
                    # TLS 1.1; failure must come from the production client.
                    context = ssl.create_default_context(cafile=str(certificates / "ca.pem"))
                    context.minimum_version = ssl.TLSVersion.TLSv1_1
                    context.maximum_version = ssl.TLSVersion.TLSv1_1
                    context.set_ciphers("DEFAULT:@SECLEVEL=0" if ssl.OPENSSL_VERSION.startswith("OpenSSL") else "DEFAULT")
                    context.load_cert_chain(certificates / "client.pem", certificates / "client.key")
                    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
                        with context.wrap_socket(raw, server_hostname="companion.localhost") as tls:
                            legacy_fixture_protocol = tls.version()
                            assert legacy_fixture_protocol == "TLSv1.1"
                leaf = mode if mode in ["wrong-host", "expired"] else "server"
                pin = hashlib.sha256((certificates / f"{leaf}.der").read_bytes()).hexdigest()
                config = {
                    "endpoint": f"{'http' if variant == 'http' else 'https'}://companion.localhost:{port}",
                    "ca": str(certificates / ("other-ca.der" if variant == "ca" else "ca.der")),
                    "pin": "0" * 64 if variant == "pin" else pin,
                    "identity": str(certificates / f"{variant if variant in ['foreign', 'revoked'] else 'client'}.p12"),
                    "command": "authentication-unlock" if mode == "authentication-unlock422" else "authentication" if mode.startswith("authentication") else "drop" if mode == "drop" else "session",
                    "review": str(ROOT / "tests/fixtures/companion/review.json"),
                }
                setup = work / "probe.json"; setup.write_text(json.dumps(config))
                result = subprocess.run([str(bundles[bundle]), str(setup)], capture_output=True, text=True, timeout=30)
                (report / f"{name}.log").write_text(result.stdout + result.stderr)
                assert result.returncode == 0, f"{name}: probe failed ({result.returncode})"
                response = json.loads(result.stdout.strip().splitlines()[-1])
                observed = [json.loads(line)["command"] for line in (certificates / "requests.jsonl").read_text().splitlines()]
                record = {"case": name, "response": response, "commands": observed, "passed": response["bundled"] and response["cleanup_verified"] and response["success"] == expected and observed == commands}
                if legacy_fixture_protocol:
                    record["legacy_fixture_protocol"] = legacy_fixture_protocol
                if variant == "http":
                    record["passed"] = record["passed"] and response.get("configuration_rejected") is True
                if mode.startswith("authentication"):
                    record["passed"] = record["passed"] and response.get("rejection") == "authentication_failed"
                if mode in ["success503", "error200", "mismatched-error422", "unknown-error422", "extra-error422"]:
                    record["passed"] = record["passed"] and response.get("error") == "Provider returned an invalid response." and "rejection" not in response
                if mode == "drop":
                    record["passed"] = record["passed"] and response.get("lost_reply") and response.get("status") == "pending"
                records.append(record)
                (report / "results.json").write_text(json.dumps(records, indent=2) + "\n")
                print(f"{name}: {'PASS' if record['passed'] else 'FAIL'}", flush=True)
                assert record["passed"], f"{name}: {response}; commands={observed}"
            finally:
                server.terminate(); server.wait(timeout=10); server_log.close()
        hashes = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in [*sources, ROOT / "scripts/build-macos-companion.sh", FIXTURES / "BundleProbe.swift", FIXTURES / "bundle_tls.py", FIXTURES / "tls_fixture.py"]}
        (report / "source-hashes.json").write_text(json.dumps(hashes, indent=2, sort_keys=True) + "\n")
    print(f"Bundle TLS regression: {len(records)} passed; 0 skipped.", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--strict-only", action="store_true")
    modes.add_argument("--evaluate-proposal", action="store_true")
    parser.add_argument("--case", action="append", dest="selected_cases", help="Run only this named case; repeat to select multiple cases")
    args = parser.parse_args()
    run(args.report.resolve(), args.strict_only, args.evaluate_proposal, args.selected_cases)
