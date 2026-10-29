#!/usr/bin/env python3
"""Stage-zero observations, never a macOS execution provider.

Exit 2 means blocked/unavailable (including a completed observation run), 1
means a probe or cleanup failed. There is intentionally no qualified exit 0.
Only --help exits 0. Native observations require explicit host authorization.
"""
import argparse
from contextlib import ExitStack, closing
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import secrets
import select
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[3]
SOURCES = [
    "scripts/test-macos-boundary.sh",
    "tests/fixtures/macos-boundary/probe.c",
    "tests/fixtures/macos-boundary/qualify.py",
    "tests/fixtures/macos-boundary/test_qualify.py",
    "tests/fixtures/macos-boundary/README.md",
    "docs/native-macos-plan.md",
    "docs/implementation/issue-49-qualification/README.md",
    "docs/implementation/issue-49-qualification/privileged-setup-plan.md",
    "src/lib.rs", "src/access/ports.rs", "src/adapters/execution.rs",
    "src/adapters/supervisor.rs", "tests/unsupported_provider_platform.rs",
    "companion/macos/Runner/NativeTestKey.swift",
]
POLICY_CONTRACT = "secret-access-only-2026-10-28"
# New reports follow the access-only contract. Historical reports stay unchanged.
# An observation pass never turns any of these production gates into a pass.
GATES = {
    "separate-agent-identities": "authorized-dedicated-provider-and-agent-accounts-required",
    "wrong-uid": "real-cross-account-transport-required",
    "wrong-key": "candidate-enrollment-and-ed25519-verifier-required",
    "socket-substitution": "connection-bound-server-and-client-identity-required",
    "replacement": "no-writer-lifetime-and-exact-executed-image-contract-required",
    "mutation-symlink-hardlink": "protected-stage-and-concurrent-attacker-required",
    "unsafe-dependency-signature": "dependency-closure-and-production-signing-policy-required",
    "agent-inspection": "cross-account-argv-env-memory-files-logs-inspection-required",
    "consumer-resource-lifetime": "safe-resource-handoff-and-disuse-evidence-required-without-termination",
    "consumer-execution-independence": "consumer-survival-after-main-exit-and-access-loss-required",
    "provider-controller-crash": "future-delivery-invalidation-and-consumer-survival-required",
    "expiry-lock-cancel-revoke": "future-delivery-denial-and-release-race-evidence-required",
    "restart-invalidation": "persistent-ownership-and-fresh-unlock-recovery-required",
    "service-keychain": "authorized-nonlogin-service-keychain-qualification-required",
    "production-signing": "developer-id-hardened-runtime-and-distribution-evidence-required",
    "unsupported-platform-regression": "native-cargo-regression-required",
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=path.name + ".", suffix=".pending", delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
        sync_directory(path.parent)
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass  # Failure cleanup inventories any retained partial report.


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


FAILURE_CODES = {
    "run-deadline", "tool-deadline", "tool-failed", "tool-output-limit",
    "controller-interrupted", "registration-deadline", "registration-invalid",
    "registration-eof", "identity-disagreement", "parent-identity-mismatch",
    "synthetic-secret-visible", "inspection-control-missing", "independent-exit-evidence-missing",
    "fixture-exit-unexpected", "setsid-not-observed", "peer-result-invalid",
    "replacement-not-demonstrated", "mutated-image-accepted", "source-read-failed",
    "evidence-write-failed", "cleanup-direct-child-failed", "cleanup-inventory-failed",
    "cleanup-failed-resources-retained", "io-failed", "protocol-invalid", "probe-failed-details-redacted",
}


class ProbeFailure(Exception):
    """Fixed diagnostics only; never include child output or exception text."""


def interrupted(_signum, _frame):
    raise ProbeFailure("controller-interrupted")


class Run:
    def __init__(self, output):
        self.output = output
        self.observations = []
        self.processes = []
        self.resources = []
        self.children = []
        self.uncertain = False
        self.failed = False
        self.failures = []
        self.active_case = "initialization"
        self.source_snapshot = output / "source-snapshot" / "probe.c"
        self.source_hashes = {}
        self.deadline = time.monotonic() + 180
        self.env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C",
                    "TMPDIR": str(output)}

    def failure(self, error, code=None):
        if code is None:
            if isinstance(error, ProbeFailure) and error.args and error.args[0] in FAILURE_CODES:
                code = error.args[0]
            elif isinstance(error, KeyboardInterrupt):
                code = "controller-interrupted"
            elif isinstance(error, subprocess.TimeoutExpired):
                code = "tool-deadline"
            elif isinstance(error, OSError):
                code = "io-failed"
            elif isinstance(error, (ValueError, KeyError, TypeError)):
                code = "protocol-invalid"
            else:
                code = "probe-failed-details-redacted"
        assert code in FAILURE_CODES
        self.failed = self.uncertain = True
        self.failures.append({"code": code, "case": self.active_case})

    def best_effort_save(self, name, value):
        try:
            save(self.output / name, value)
            return True
        except (OSError, ValueError, ProbeFailure, KeyboardInterrupt) as error:
            self.failure(error, None if isinstance(error, (ProbeFailure, KeyboardInterrupt)) else "evidence-write-failed")
            return False

    def snapshot_sources(self):
        hashes = self.source_hashes
        self.source_snapshot.parent.mkdir(mode=0o700)
        for name in SOURCES:
            try:
                data = (ROOT / name).read_bytes()
            except OSError:
                raise ProbeFailure("source-read-failed") from None
            hashes[name] = hashlib.sha256(data).hexdigest()
            if name == "tests/fixtures/macos-boundary/probe.c":
                with self.source_snapshot.open("xb") as stream:
                    stream.write(data)
                    stream.flush()
                    os.fchmod(stream.fileno(), 0o400)
                    os.fsync(stream.fileno())
                sync_directory(self.source_snapshot.parent)
                sync_directory(self.output)
        save(self.output / "source-hashes.json", hashes)
        return hashes

    def sdk_available(self):
        self.active_case = "sdk-prerequisites"
        try:
            self.command(["/usr/bin/xcrun", "--find", "clang"])
            self.command(["/usr/bin/xcrun", "--show-sdk-path"])
        except ProbeFailure as error:
            if error.args == ("tool-failed",):
                return False
            raise
        return True

    def manifest(self):
        save(self.output / "resources.json", {
            "schema": 1, "owner_uid": os.geteuid(), "processes": self.processes,
            "files": self.resources, "protected_material_reusable": False,
        })

    def record_file(self, path, kind):
        info = path.lstat()
        self.resources.append({"path": str(path.relative_to(self.output)), "kind": kind,
                               "uid": info.st_uid, "mode": oct(stat.S_IMODE(info.st_mode)),
                               "device": info.st_dev, "inode": info.st_ino,
                               "retained": True})
        self.manifest()

    def remaining(self, limit=15):
        remaining = min(limit, self.deadline - time.monotonic())
        if remaining <= 0:
            raise ProbeFailure("run-deadline")
        return remaining

    def command(self, argv, *, timeout=15, allowed=(0,), capture=False, stderr=False):
        # Output is written to a private, bounded-by-RLIMIT_FSIZE scratch file,
        # never echoed or copied into a report. Compiler diagnostics can include
        # arbitrary paths; signature output is explicitly reduced below.
        with tempfile.TemporaryFile(dir=self.output) as stream:
            self.remaining(timeout)  # Never spawn after the run budget expires.
            child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stream,
                                     stderr=stream if stderr else subprocess.DEVNULL, env=self.env,
                                     close_fds=True, cwd=self.output)
            self.children.append(child)
            record = {"pid": child.pid, "kind": "direct-tool", "waited": False}
            self.processes.append(record)
            self.manifest()
            try:
                child.wait(timeout=self.remaining(timeout))
            except subprocess.TimeoutExpired:
                child.kill()  # unreaped direct child cannot have its PID reused
                child.wait(timeout=3)
                raise ProbeFailure("tool-deadline") from None
            finally:
                record["waited"] = child.poll() is not None
                record["exit_code"] = child.returncode
                self.manifest()
            if child.returncode not in allowed:
                raise ProbeFailure("tool-failed")
            if capture:
                stream.seek(0)
                data = stream.read(65537)
                if len(data) > 65536:
                    raise ProbeFailure("tool-output-limit")
                return data
            return child.returncode

    def observation(self, case, outcome, detail):
        self.observations.append({"case": case, "outcome": outcome, "detail": detail,
                                  "production_gate_satisfied": False})
        save(self.output / "observations.json", self.observations)

    def register(self, process, queue, stream, *, secret=None):
        if secret is not None:
            process.stdin.write(secret)
            process.stdin.flush()
        ready, _, _ = select.select([stream], [], [], self.remaining(3))
        if not ready:
            raise ProbeFailure("registration-deadline")
        # Each fixture is gated after its one <=384-byte atomic record. Reading
        # one byte at a time prevents buffering a subsequent descendant record.
        record = bytearray()
        until = time.monotonic() + self.remaining(3)
        while not record.endswith(b"\n"):
            if len(record) >= 384 or time.monotonic() >= until:
                raise ProbeFailure("registration-invalid")
            ready, _, _ = select.select([stream], [], [], max(0, until - time.monotonic()))
            if not ready:
                raise ProbeFailure("registration-deadline")
            value = os.read(stream.fileno(), 1)
            if not value:
                raise ProbeFailure("registration-eof")
            record += value
        claimed = json.loads(record)
        keys = {"pid", "ppid", "pgid", "uid", "start_sec", "start_usec"}
        if (set(claimed) != keys or any(type(v) is not int or v < 0 for v in claimed.values())
                or claimed["pid"] <= 1 or claimed["uid"] != os.geteuid()):
            raise ProbeFailure("registration-invalid")
        # Observe from a separate process through libproc, then subscribe to a
        # kernel NOTE_EXIT while the target is still blocked at its release gate.
        independent = json.loads(self.command([str(self.binary), "observe", str(claimed["pid"])],
                                               capture=True))
        if any(claimed[key] != independent[key] for key in keys - {"ppid"}):
            raise ProbeFailure("identity-disagreement")
        claimed["ppid"] = independent["ppid"]  # reparenting is allowed
        queue.control([select.kevent(claimed["pid"], filter=select.KQ_FILTER_PROC,
                                     flags=select.KQ_EV_ADD | select.KQ_EV_ONESHOT,
                                     fflags=select.KQ_NOTE_EXIT)], 0, 0)
        claimed.update({"kind": "fixture", "kernel_exit_observed": False,
                        "waited": False, "released": False})
        self.processes.append(claimed)
        self.manifest()  # Durable ownership before release.
        return claimed

    def fixture(self, mode, *, crash_parent=False):
        self.active_case = mode + ("-parent-crash" if crash_parent else "")
        control_read, control_write = os.pipe()
        try:
            self.remaining()
            arguments = [str(self.binary), mode, str(control_read)]
            environment = dict(self.env)
            if mode == "inspection":
                arguments.append("vw49-argv-control")
                environment["VW49_INSPECTION_CONTROL"] = "vw49-visible-control"
            process = subprocess.Popen(arguments, stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                       env=environment, close_fds=True, start_new_session=True,
                                       pass_fds=(control_read,), cwd=self.output)
        except (Exception, KeyboardInterrupt):
            os.close(control_write)
            raise
        finally:
            os.close(control_read)
        self.children.append(process)
        owner = {"pid": process.pid, "kind": "fixture-parent", "waited": False}
        self.processes.append(owner)
        with ExitStack() as descriptors:
            descriptors.callback(os.close, control_write)
            descriptors.callback(process.stdin.close)
            descriptors.callback(process.stdout.close)
            self.manifest()
            owned = []
            # Python 3.9 kqueue has close(), but no context-manager protocol.
            queue = descriptors.enter_context(closing(select.kqueue()))
            try:
                synthetic = secrets.token_hex(32).encode() if mode == "inspection" else None
                count = 3 if mode == "descendants" else 1
                for index in range(count):
                    item = self.register(process, queue, process.stdout,
                                         secret=synthetic if index == 0 else None)
                    owned.append(item)
                    if index == 0 and item["pid"] != process.pid:
                        raise ProbeFailure("parent-identity-mismatch")
                    if mode == "inspection":
                        view = self.command(["/bin/ps", "eww", "-p", str(process.pid), "-o", "pid=", "-o", "command="],
                                            capture=True)
                        self.check_inspection(view, process.pid, synthetic)
                    if crash_parent and index == 2:
                        # The root waits on its dedicated gate until killed;
                        # the grandchild is still gated on stdin.
                        process.kill()
                    elif mode == "descendants" and index == 2:
                        os.write(control_write, b"R")
                    process.stdin.write(b"R")
                    process.stdin.flush()
                    item["released"] = True
                    self.manifest()
                pending = {item["pid"] for item in owned}
                until = time.monotonic() + self.remaining(10)
                while pending and time.monotonic() < until:
                    for event in queue.control(None, 16, max(0, until - time.monotonic())):
                        if event.ident in pending and event.fflags & select.KQ_NOTE_EXIT:
                            pending.remove(event.ident)
                            next(item for item in owned if item["pid"] == event.ident)["kernel_exit_observed"] = True
                process.wait(timeout=self.remaining(3))
                owner["waited"] = True
                owned[0]["waited"] = True
                if pending:
                    raise ProbeFailure("independent-exit-evidence-missing")
                expected = -signal.SIGABRT if mode == "crash" else 0
                if process.returncode != (-signal.SIGKILL if crash_parent else expected):
                    raise ProbeFailure("fixture-exit-unexpected")
                if mode == "descendants":
                    if owned[-1]["pgid"] == owned[0]["pgid"]:
                        raise ProbeFailure("setsid-not-observed")
                    # NOTE_EXIT does not prove a production fork barrier or
                    # independently establish non-child zombie reaping.
                    self.uncertain = True
                return owned
            finally:
                self.manifest()

    def check_inspection(self, view, pid, synthetic):
        columns = view.strip().split(maxsplit=1)
        if (len(columns) != 2 or columns[0] != str(pid).encode()
                or str(self.binary).encode() not in columns[1]
                or b" inspection " not in columns[1]
                or b"vw49-argv-control" not in columns[1]
                or b"VW49_INSPECTION_CONTROL=vw49-visible-control" not in columns[1]):
            raise ProbeFailure("inspection-control-missing")
        if synthetic in view:
            raise ProbeFailure("synthetic-secret-visible")

    def native(self):
        self.binary = self.output / "probe-original"
        alternate = self.output / "probe-replacement"
        for binary, variant in [(self.binary, "original"), (alternate, "replacement")]:
            self.active_case = "build-" + variant
            self.command(["/usr/bin/xcrun", "clang", "-arch", "arm64", "-mmacosx-version-min=13.0",
                          "-Wall", "-Wextra", "-Werror", "-O2", '-DIMAGE_VARIANT="' + variant + '"',
                          str(self.source_snapshot), "-o", str(binary)], timeout=45)
            self.active_case = "sign-" + variant
            self.command(["/usr/bin/codesign", "--force", "--sign", "-", "--options", "runtime",
                          "--timestamp=none", str(binary)])
            self.command(["/usr/bin/codesign", "--verify", "--strict", str(binary)])
            self.record_file(binary, "ad-hoc-hardened-runtime-fixture")
        # This harness only creates ad-hoc fixtures with no entitlements. It
        # deliberately makes no claim about Developer ID or notarization.
        signatures = []
        for binary in [self.binary, alternate]:
            self.active_case = "signature-metadata-" + binary.name
            display = self.command(["/usr/bin/codesign", "--display", "--verbose=4", str(binary)],
                                   capture=True, stderr=True).decode("utf-8", errors="replace")
            signature_fields = {}
            for line in display.splitlines():
                key, separator, value = line.partition("=")
                if separator and key in {"Identifier", "CDHash", "TeamIdentifier", "CodeDirectory", "Signature"}:
                    signature_fields[key] = value
            signatures.append({"path": binary.name, "sha256": digest(binary),
                               "signature": "ad-hoc", "hardened_runtime_requested": True,
                               "entitlements_requested": {}, "strict_verification": "pass",
                               "production_distribution_evidence": False,
                               "codesign_fields": signature_fields})
        save(self.output / "signatures.json", signatures)
        self.observation("signed-fixtures", "pass", "ad-hoc-signatures-only")
        for mismatch in [False, True]:
            self.active_case = "peer-expected-uid-mismatch" if mismatch else "peer-kernel-uid"
            left, right = socket.socketpair()
            try:
                expected = os.geteuid() + 1 if mismatch else os.geteuid()
                self.remaining(3)
                child = subprocess.Popen([str(self.binary), "peer", str(right.fileno()), str(expected)],
                                         pass_fds=(right.fileno(),), stdout=subprocess.PIPE,
                                         stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, env=self.env)
                self.children.append(child)
                entry = {"pid": child.pid, "kind": "peer-fixture", "waited": False}
                self.processes.append(entry)
                self.manifest()
                output, _ = child.communicate(timeout=self.remaining(3))
                entry["waited"] = True
                entry["exit_code"] = child.returncode
                self.manifest()
                if (child.returncode, output) != ((77, b"denied\n") if mismatch else (0, b"peer-matched\n")):
                    raise ProbeFailure("peer-result-invalid")
                self.observation("peer-expected-uid-mismatch" if mismatch else "peer-kernel-uid",
                                 "pass", "socketpair-same-account-no-secret-release")
            finally:
                left.close(); right.close()
        self.active_case = "pathname-replacement-negative-control"
        launch = self.output / "path-launch"
        shutil.copyfile(self.binary, launch)
        launch.chmod(0o700)
        before = digest(launch)
        replacement = self.output / "replacement-staging"
        shutil.copyfile(alternate, replacement)
        replacement.chmod(0o700)
        replacement.replace(launch)
        self.record_file(launch, "deliberately-writable-path-candidate")
        output = self.command([str(launch), "image"], capture=True)
        if output != b"replacement\n" or before == digest(launch):
            raise ProbeFailure("replacement-not-demonstrated")
        save(self.output / "replacement.json", {"checked_sha256": before,
                                               "launched_sha256": digest(launch),
                                               "exec_marker": "replacement"})
        self.observation("pathname-replacement-negative-control", "pass", "checked-path-executed-different-bytes-candidate-rejected")
        self.active_case = "signature-mutation-negative-control"
        corrupted = self.output / "mutated-image"
        shutil.copyfile(self.binary, corrupted)
        with corrupted.open("r+b") as stream:
            stream.write(b"INVALID-MACH-O!!!")
        self.record_file(corrupted, "deliberate-invalid-image")
        status = self.command(["/usr/bin/codesign", "--verify", "--strict", str(corrupted)], allowed=(0, 1))
        if status == 0:
            raise ProbeFailure("mutated-image-accepted")
        self.observation("signature-mutation-negative-control", "pass", "invalid-image-denied-before-launch")
        material = self.output / "synthetic-material.private"
        material.write_bytes(secrets.token_bytes(64))
        self.record_file(material, "synthetic-protected-material-retain-on-uncertainty")
        for mode, crash in [("inspection", False), ("crash", False),
                            ("descendants", False), ("descendants", True)]:
            self.fixture(mode, crash_parent=crash)
            self.observation(mode + ("-parent-crash" if crash else ""), "pass",
                             "bounded-fixture-observation-not-production-cleanup-proof")

    def cleanup(self):
        # Only unreaped direct children are signalled. Detached descendants have
        # an eight-second SIGALRM and continuous-clock lifetime limit. We never
        # kill by unverified PID/group, delete material, or recycle any identity.
        for child in self.children:
            try:
                if child.poll() is None:
                    child.kill()
            except (OSError, subprocess.SubprocessError, ProbeFailure, KeyboardInterrupt) as error:
                self.failure(error, "cleanup-direct-child-failed")
            try:
                if child.returncode is None:
                    child.wait(timeout=3)
            except (OSError, subprocess.SubprocessError, ProbeFailure, KeyboardInterrupt) as error:
                self.failure(error, "cleanup-direct-child-failed")
            for item in self.processes:
                if item["pid"] == child.pid and item["kind"] != "fixture":
                    item["waited"] = child.returncode is not None
                    item["exit_code"] = child.returncode
        unobserved = [item["pid"] for item in self.processes
                      if item["kind"] == "fixture" and not item["kernel_exit_observed"]]
        if unobserved:
            self.uncertain = True
        try:
            self.inventory()
        except (OSError, ProbeFailure, KeyboardInterrupt) as error:
            self.failure(error, "cleanup-inventory-failed")
        self.best_effort_save("resources.json", {
            "schema": 1, "owner_uid": os.geteuid(), "processes": self.processes,
            "files": self.resources, "protected_material_reusable": False,
        })
        self.best_effort_save("cleanup.json", {
            "outcome": "uncertain-retained" if self.uncertain else "direct-children-accounted",
            "unobserved_registered_pids": unobserved,
            "unregistered_descendants_possible_after_failure": self.failed,
            "production_cleanup_evidence": "Unavailable",
            "material_deleted": False, "resources_retained": True,
            "identity_reuse_permitted": False,
            "note": "kernel-exit-is-not-independent-reap-or-an-atomic-fork-barrier",
        })

    def inventory(self):
        # This new run directory is task-owned. Include partial compiler/signing
        # artifacts and pending reports; inspect metadata only, never contents.
        known = {item["path"]: item for item in self.resources}
        pending = [self.output]
        count = 0
        while pending:
            directory = pending.pop()
            with os.scandir(directory) as entries:
                for entry in entries:
                    count += 1
                    if count > 4096:
                        raise ProbeFailure("cleanup-inventory-failed")
                    info = entry.stat(follow_symlinks=False)
                    path = Path(entry.path)
                    relative = str(path.relative_to(self.output))
                    known[relative] = {"path": relative,
                                       "kind": known.get(relative, {}).get("kind", "retained-task-artifact"),
                                       "uid": info.st_uid, "mode": oct(stat.S_IMODE(info.st_mode)),
                                       "device": info.st_dev, "inode": info.st_ino, "retained": True}
                    if stat.S_ISDIR(info.st_mode):
                        pending.append(path)
        self.resources = list(known.values())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new private evidence directory (must not exist)")
    parser.add_argument("--authorized-disposable-host", action="store_true",
                        help="assert separate explicit authorization for this disposable Mac; never grants privileged setup")
    args = parser.parse_args(argv)
    os.umask(0o077)
    output = args.output.absolute()
    try:
        # Resolve the parent before creating a new leaf; existing evidence is
        # never overwritten. Do not allow an agent-writable evidence directory.
        parent = output.parent.resolve(strict=True)
        info = parent.stat()
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o022:
            raise OSError()
        output = parent / output.name
        output.mkdir(mode=0o700)
    except OSError:
        print("qualification: output requires a new directory in an owner-private writable parent", file=sys.stderr)
        return 2
    run = Run(output)
    environment = {"system": platform.system(), "architecture": platform.machine(),
                   "kernel_release": platform.release(), "uid": os.geteuid(),
                   "native_host_authorized": args.authorized_disposable_host,
                   "os_build": None, "os_version": None, "api_baseline": "13.0",
                   "certified_versions": []}
    source_complete = False
    gates = [{"case": name, "outcome": "unavailable", "reason": reason,
              "policy_contract": POLICY_CONTRACT} for name, reason in GATES.items()]
    reason = "native-macos-arm64-required"
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        _, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
        resource.setrlimit(resource.RLIMIT_FSIZE, (min(1048576, hard) if hard != resource.RLIM_INFINITY else 1048576, hard))
        run.active_case = "source-snapshot"
        run.snapshot_sources()
        source_complete = True
        run.active_case = "host-prerequisites"
        if environment["system"] == "Darwin" and environment["architecture"] == "arm64":
            environment["os_version"] = run.command(["/usr/bin/sw_vers", "-productVersion"], capture=True).decode().strip()
            environment["os_build"] = run.command(["/usr/bin/sw_vers", "-buildVersion"], capture=True).decode().strip()
            translated = run.command(["/usr/sbin/sysctl", "-in", "sysctl.proc_translated"],
                                     allowed=(0, 1), capture=True).strip()
            if translated == b"1":
                reason = "rosetta-unsupported"
            elif int(environment["os_version"].split(".")[0]) < 13:
                reason = "macos-api-baseline-unavailable"
            elif not args.authorized_disposable_host:
                reason = "native-host-authorization-required"
            elif os.geteuid() == 0:
                reason = "unprivileged-disposable-operator-required"
            elif not source_complete:
                reason = "source-manifest-incomplete"
            elif not all(Path(name).is_file() for name in ["/usr/bin/xcrun", "/usr/bin/codesign"]):
                reason = "native-build-signing-tools-unavailable"
            else:
                # A missing compiler/SDK is an unavailable prerequisite, not a
                # failed security case. No fixture runs before this succeeds.
                if not run.sdk_available():
                    reason = "native-sdk-unavailable"
                else:
                    run.native()
                    reason = "production-contracts-and-cross-account-native-evidence-missing"
    except (Exception, KeyboardInterrupt) as error:
        run.failure(error)
        run.observations.append({"case": run.active_case, "outcome": "fail",
                                 "detail": run.failures[-1]["code"], "production_gate_satisfied": False})
    finally:
        # Process cleanup does not depend on successful report publication.
        run.active_case = "cleanup"
        try:
            run.cleanup()
        except (OSError, subprocess.SubprocessError, ProbeFailure, KeyboardInterrupt) as error:
            run.failure(error, "cleanup-failed-resources-retained")
            run.best_effort_save("cleanup.json", {"outcome": "uncertain-retained",
                                           "production_cleanup_evidence": "Unavailable",
                                           "material_deleted": False, "resources_retained": True,
                                           "identity_reuse_permitted": False,
                                           "reason": "cleanup-failed-resources-retained"})
        run.active_case = "final-reports"
        for name, value in [("environment.json", environment), ("matrix.json", gates),
                            ("source-hashes.json", run.source_hashes), ("observations.json", run.observations)]:
            run.best_effort_save(name, value)
        try:
            run.inventory()
        except (OSError, ProbeFailure, KeyboardInterrupt) as error:
            run.failure(error, "cleanup-inventory-failed")
        run.best_effort_save("resources.json", {
            "schema": 1, "owner_uid": os.geteuid(), "processes": run.processes,
            "files": run.resources, "protected_material_reusable": False,
        })
        def result():
            return {"schema": 1, "outcome": "failed" if run.failed else "blocked",
                    "policy_contract": POLICY_CONTRACT,
                    "reason": run.failures[0]["code"] if run.failures else reason,
                    "failures": list(run.failures), "production_enabled": False,
                    "mechanism_selected": None, "certified_versions": [],
                    "source_manifest_complete": source_complete, "observations": len(run.observations)}
        # A publication can fail after rename (e.g. directory fsync). Retry once
        # with closed failure accounting so any readable result says failed.
        if not run.best_effort_save("result.json", result()):
            run.best_effort_save("result.json", result())
    print("qualification: " + ("failed" if run.failed else "blocked") + "; production remains disabled")
    print("evidence: " + str(output))
    return 1 if run.failed else 2


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, interrupted)
    raise SystemExit(main())
