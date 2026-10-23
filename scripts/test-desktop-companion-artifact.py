#!/usr/bin/env python3
"""Portable artifact and release-result checks, without any native signing."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location(
    "artifact", Path(__file__).with_name("desktop-companion-artifact.py"))
ARTIFACT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ARTIFACT)


class ArtifactTests(unittest.TestCase):
    def test_pilot_archive_and_metadata_never_overwrite_normal_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "app"
            root.mkdir()
            (root / "synthetic").write_bytes(b"synthetic executable")
            evidence = Path(temporary) / "evidence"
            evidence.mkdir()
            normal = ARTIFACT.package(root, evidence, "macos", "revision", False)
            original = normal.read_bytes()
            metadata = (evidence / "artifact.json").read_bytes()
            pilot = ARTIFACT.package(root, evidence, "macos", "revision", False, True)
            self.assertNotEqual(normal, pilot)
            self.assertEqual(normal.read_bytes(), original)
            self.assertEqual((evidence / "artifact.json").read_bytes(), metadata)
            self.assertTrue(json.loads((evidence / "pilot-artifact.json").read_text())["disposable_test_only"])
            with tarfile.open(pilot) as source:
                self.assertIn("companion_disposable_pilot.app/synthetic", source.getnames())
            with self.assertRaises(ValueError):
                ARTIFACT.package(root, evidence, "linux", "revision", False, True)

    def test_archive_preserves_executable_and_framework_link(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "app"
            evidence = Path(temporary) / "evidence"
            binary = root / "Contents/MacOS/companion_slice"
            binary.parent.mkdir(parents=True)
            evidence.mkdir()
            binary.write_bytes(b"synthetic executable")
            binary.chmod(0o755)
            framework = root / "Contents/Frameworks/Example.framework/Versions"
            (framework / "A").mkdir(parents=True)
            (framework / "A/Example").write_bytes(b"synthetic framework")
            # Windows bundles do not contain framework links. macOS/Linux must
            # exercise the symlink preservation rather than silently skip it.
            if os.name != "nt":
                (framework / "Current").symlink_to("A", target_is_directory=True)
            archive = ARTIFACT.package(root, evidence, "macos", "test-revision", False)
            with tarfile.open(archive) as source:
                member = source.getmember("companion_slice.app/Contents/MacOS/companion_slice")
                if os.name != "nt":
                    self.assertTrue(member.mode & 0o111)
                if os.name != "nt":
                    link = source.getmember("companion_slice.app/Contents/Frameworks/Example.framework/Versions/Current")
                    self.assertTrue(link.issym())
                    self.assertEqual(link.linkname, "A")
            metadata = json.loads((evidence / "artifact.json").read_text())
            self.assertEqual(metadata["sha256"], ARTIFACT.digest(archive))
            self.assertEqual(metadata["source_revision"], "test-revision")
            self.assertTrue(metadata["extraction_verified"])
            self.assertFalse(metadata["source_dirty"])

    def test_success_requires_runtime_marker_and_zero_exit(self):
        with tempfile.TemporaryDirectory() as temporary:
            evidence = Path(temporary)
            for code, stdout, passes in [
                (0, b"", False), (1, b"COMPANION_RELEASE_SMOKE_OK\n", False),
                (0, b"COMPANION_RELEASE_SMOKE_OK\n", True),
            ]:
                result = subprocess.CompletedProcess([], code, stdout, b"")
                with patch.object(ARTIFACT.subprocess, "run", return_value=result):
                    if passes:
                        ARTIFACT.smoke(Path("synthetic"), evidence)
                    else:
                        with self.assertRaises(RuntimeError):
                            ARTIFACT.smoke(Path("synthetic"), evidence)

    def test_windows_result_file_is_required_without_console_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            evidence = Path(temporary)
            def run(_command, **options):
                Path(options["env"]["COMPANION_RELEASE_RESULT"]).write_bytes(b"COMPANION_RELEASE_SMOKE_OK\n")
                return subprocess.CompletedProcess([], 0, b"", b"")
            with patch.object(ARTIFACT.subprocess, "run", side_effect=run):
                ARTIFACT.smoke(Path("synthetic"), evidence, use_file=True)
            with patch.object(ARTIFACT.subprocess, "run",
                              return_value=subprocess.CompletedProcess([], 0, b"", b"")):
                with self.assertRaises(RuntimeError):
                    ARTIFACT.smoke(Path("synthetic"), evidence, use_file=True)

    def test_timeout_fails_and_preserves_diagnostics(self):
        with tempfile.TemporaryDirectory() as temporary:
            evidence = Path(temporary)
            with patch.object(ARTIFACT.subprocess, "run",
                              side_effect=subprocess.TimeoutExpired([], 60, output=b"started\n")):
                with self.assertRaises(subprocess.TimeoutExpired):
                    ARTIFACT.smoke(Path("synthetic"), evidence)
            self.assertIn(b"timed out", (evidence / "release-smoke.log").read_bytes())
            self.assertFalse(json.loads((evidence / "release-smoke-result.json").read_text())["checks_passed"])

    @unittest.skipIf(os.name == "nt", "Windows bundles have no framework symlinks")
    def test_archive_rejects_external_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "app"
            root.mkdir()
            (root / "outside").symlink_to(root.parent, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "external symlink"):
                ARTIFACT.inventory(root)


if __name__ == "__main__":
    unittest.main()
