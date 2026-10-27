#!/usr/bin/env python3
"""Check the release smoke executable and archive normal-entry desktop bundles."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tarfile
import tempfile


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def inventory(root):
    result = {}
    for path in [root, *sorted(root.rglob("*"))]:
        attributes = path.lstat()
        entry = {"mode": stat.S_IMODE(attributes.st_mode)}
        if path.is_symlink():
            target = os.readlink(path)
            # Only self-contained framework links belong in a portable bundle.
            if not path.resolve().is_relative_to(root.resolve()):
                raise ValueError("bundle has an external symlink")
            entry.update(kind="symlink", target=target)
        elif path.is_file():
            entry.update(kind="file", sha256=digest(path))
        elif path.is_dir():
            entry.update(kind="directory")
        else:
            raise ValueError("unsupported bundle member")
        result[str(path.relative_to(root))] = entry
    return result


def locate(repo, platform):
    patterns = {
        "linux": "companion/build/linux/*/release/bundle",
        "macos": "companion/build/macos/Build/Products/Release/companion_slice.app",
        "windows": "companion/build/windows/*/runner/Release",
    }
    candidates = list(repo.glob(patterns[platform]))
    if len(candidates) != 1:
        raise ValueError("expected exactly one release bundle")
    root = candidates[0]
    executable = root / {
        "linux": "companion_slice",
        "macos": "Contents/MacOS/companion_slice",
        "windows": "companion_slice.exe",
    }[platform]
    if not executable.is_file():
        raise ValueError("release executable missing")
    return root, executable


def smoke(executable, evidence, use_file=False):
    (evidence / "release-smoke-result.json").write_text(
        json.dumps({"mode": "release", "checks_passed": False}) + "\n")
    with tempfile.TemporaryDirectory(prefix="release-result-", dir=evidence) as temporary:
        marker = Path(temporary) / "result"
        environment = dict(os.environ)
        if use_file:
            environment["COMPANION_RELEASE_RESULT"] = str(marker)
        try:
            result = subprocess.run([str(executable)], capture_output=True, timeout=60, env=environment)
        except subprocess.TimeoutExpired as error:
            (evidence / "release-smoke.log").write_bytes(
                (error.stdout or b"") + (error.stderr or b"") + b"\nRelease smoke timed out.\n")
            raise
        if use_file:
            observed = marker.read_bytes() if marker.is_file() else b""
        else:
            observed = result.stdout
        (evidence / "release-smoke.log").write_bytes(
            result.stdout + result.stderr + (observed if use_file else b""))
        if result.returncode != 0 or b"COMPANION_RELEASE_SMOKE_OK" not in observed.splitlines():
            raise RuntimeError("release smoke failed; see release-smoke.log")
    (evidence / "release-smoke-result.json").write_text(json.dumps({
        "mode": "release", "exit_code": 0, "checks_passed": True,
        "result_channel": "file" if use_file else "stdout",
    }) + "\n")
    print("Release AOT bridge, native contract and rendered fixture checks passed.")


def package(root, evidence, platform, revision, dirty, disposable_pilot=False):
    if disposable_pilot and platform != "macos":
        raise ValueError("disposable pilot artifacts require macOS")
    expected = inventory(root)
    variant = "disposable-pilot" if disposable_pilot else "development"
    archive = evidence / f"companion-{platform}-{variant}.tar.gz"
    name = ("companion_disposable_pilot.app" if disposable_pilot else "companion_slice.app") if platform == "macos" else f"companion-{platform}"
    with tarfile.open(archive, "w:gz", dereference=False) as output:
        output.add(root, arcname=name)
    # The archive was just produced from our own validated build tree, not an
    # externally supplied tar. Preserve the exact modes and links on extraction.
    with tempfile.TemporaryDirectory(prefix="companion-archive-check-") as temporary:
        with tarfile.open(archive, "r:gz") as source:
            source.extractall(temporary, filter="fully_trusted")
        if inventory(Path(temporary) / name) != expected:
            raise RuntimeError("archive extraction changed bundle content or metadata")
    checksum = digest(archive)
    (evidence / f"{archive.name}.sha256").write_text(f"{checksum}  {archive.name}\n")
    (evidence / ("pilot-artifact.json" if disposable_pilot else "artifact.json")).write_text(json.dumps({
        "source_revision": revision,
        "source_dirty": dirty,
        "entrypoint": "lib/main.dart",
        "mode": "release",
        "archive": archive.name,
        "sha256": checksum,
        "extraction_verified": True,
        "members": expected,
        **({"disposable_test_only": True,
            "requested_build_flags": {"dart_define": "COMPANION_DISPOSABLE_PILOT=true",
                                      "swift_condition": "COMPANION_DISPOSABLE_PILOT"}} if disposable_pilot else {}),
    }, indent=2) + "\n")
    print(f"{'Disposable test' if disposable_pilot else 'Normal-entry'} release archive verified: {archive.name}")
    return archive


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["smoke", "package"])
    parser.add_argument("platform", choices=["linux", "macos", "windows"])
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--source-revision", help="Explicit provenance for an isolated build without Git metadata")
    parser.add_argument("--source-dirty", action="store_true")
    parser.add_argument("--disposable-pilot", action="store_true", help="Separately named opt-in disposable Mac artifact")
    args = parser.parse_args()
    if args.disposable_pilot and (args.action != "package" or args.platform != "macos"):
        parser.error("--disposable-pilot requires package macos")
    repo = Path(__file__).resolve().parents[1]
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    root, executable = locate(repo, args.platform)
    if args.action == "smoke":
        smoke(executable, evidence, use_file=args.platform == "windows")
    else:
        if args.source_revision:
            if not re.fullmatch("[0-9a-f]{40}", args.source_revision) or not args.source_dirty:
                parser.error("isolated provenance requires a full revision and --source-dirty")
            revision, dirty = args.source_revision, True
        else:
            revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
            dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=repo))
        package(root, evidence, args.platform, revision, dirty, args.disposable_pilot)


if __name__ == "__main__":
    main()
