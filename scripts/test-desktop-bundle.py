#!/usr/bin/env python3
"""Bundle contract/provenance tests. All filesystem work uses temporary roots."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('bundle', Path(__file__).with_name('desktop-bundle.py'))
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)

class BundleTests(unittest.TestCase):
    def test_provenance_reports_exact_changed_untracked_and_deleted_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            def git(*args):
                return subprocess.check_output(['git', '-c', 'user.email=fixture@example.invalid', '-c', 'user.name=Fixture', *args], cwd=repo, stderr=subprocess.DEVNULL)
            git('init')
            (repo / 'tracked.txt').write_text('before\n')
            (repo / 'deleted.txt').write_text('original\n')
            git('add', '.'); git('commit', '-m', 'fixture')
            before = bundle.provenance(repo)
            (repo / 'tracked.txt').write_text('after\n')
            (repo / 'untracked ü.txt').write_text('new\n')
            (repo / 'deleted.txt').unlink()
            after = bundle.provenance(repo)
            self.assertFalse(before['source_dirty'])
            self.assertTrue(after['source_dirty'])
            self.assertIn('tracked.txt', after['status_porcelain_z'])
            self.assertIn('untracked ü.txt', after['status_porcelain_z'])
            self.assertIn('-before', after['diff'])
            self.assertIsNone(after['inputs']['deleted.txt'])
            self.assertNotEqual(before['inputs_sha256'], after['inputs_sha256'])

    def test_build_metadata_and_platform_commands_are_not_version_equality(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary) / 'source'; repo.mkdir()
            (repo / 'companion/rust/target/release').mkdir(parents=True)
            (repo / 'target/release').mkdir(parents=True)
            (repo / 'Cargo.toml').write_text('[package]\nversion="7.2.1"\n')
            (repo / 'companion/rust/Cargo.toml').write_text('[package]\nversion="0.1.0"\n')
            (repo / 'companion/pubspec.yaml').write_text('version: 0.1.0+1\n')
            root = Path(temporary) / 'bundle'; root.mkdir()
            for name in ['vaultwarden-cli', 'vw-access', 'vaultwarden-accessd', 'vaultwarden-access-exec']:
                p = repo / 'target/release' / name; p.write_bytes(b'synthetic'); p.chmod(0o755)
            p = repo / 'companion/rust/target/release/companion-command'; p.write_bytes(b'launcher'); p.chmod(0o755)
            for name in ['companion_slice', 'lib/libcompanion_core.so', 'lib/libapp.so', 'lib/libflutter_linux_gtk.so', 'data/icudtl.dat']:
                p = root / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(b'runtime'); p.chmod(0o755)
            source = {'revision': 'a' * 40, 'inputs_sha256': 'b' * 64}
            with patch.dict(os.environ, {}, clear=True):
                manifest = bundle.populate(repo, root, 'linux', source)
            self.assertEqual(manifest['cli_version'], '7.2.1')
            self.assertEqual(manifest['app_version'], '0.1.0+1')
            self.assertEqual(set(manifest['commands']), {'vaultwarden-cli', 'vw-access'})
            self.assertTrue(manifest['roles']['protected_provider'])
            self.assertFalse(manifest['roles']['desktop_approval'])
            (root / 'lib/libapp.so').write_bytes(b'damaged')
            with self.assertRaisesRegex(ValueError, 'damaged'):
                bundle.verify(root, manifest)

if __name__ == '__main__':
    unittest.main()
