#!/usr/bin/env python3
"""Bundle contract/provenance tests. All filesystem work uses temporary roots."""
import importlib.util
import json
import os
import plistlib
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
    def test_app_build_resolves_platform_launcher_and_preserves_checked_arguments(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            for platform, launcher in [('windows', 'flutter.bat'), ('linux', 'flutter'), ('macos', 'flutter')]:
                resolved = str(repo / 'Flutter SDK' / 'bin' / launcher)
                with patch.object(bundle.shutil, 'which', return_value=resolved) as which, patch.object(bundle.subprocess, 'run') as run, patch.object(bundle.host_platform, 'machine', return_value='x86_64'):
                    bundle.build_app(repo, platform, repo)
                which.assert_called_once_with(launcher, path=os.environ.get('PATH'))
                self.assertEqual(run.call_args.args[0], [resolved, 'build', platform, '--release', '--target', 'lib/main.dart'])
                self.assertEqual(run.call_args.kwargs['cwd'], repo / 'companion')
                self.assertTrue(run.call_args.kwargs['check'])
                self.assertNotIn('shell', run.call_args.kwargs)
            with patch.object(bundle.shutil, 'which', return_value=None), patch.object(bundle.subprocess, 'run') as run:
                with self.assertRaisesRegex(FileNotFoundError, 'flutter.bat'):
                    bundle.build_app(repo, 'windows', repo)
                run.assert_not_called()

    @unittest.skipUnless(os.name == 'nt', 'exercises native Windows batch launcher resolution')
    def test_windows_app_build_invokes_batch_launcher_from_path_with_spaces(self):
        with tempfile.TemporaryDirectory(prefix='Flutter launcher ') as temporary:
            repo = Path(temporary)
            (repo / 'companion').mkdir()
            sdk = repo / 'SDK with spaces'; sdk.mkdir()
            (sdk / 'flutter.bat').write_bytes(b'@echo off\r\necho %*>invocation.txt\r\nexit /b 0\r\n')
            with patch.dict(os.environ, {'PATH': str(sdk)}):
                bundle.build_app(repo, 'windows', repo)
            self.assertEqual((repo / 'companion/invocation.txt').read_text().strip(), 'build windows --release --target lib/main.dart')

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

    @unittest.skipIf(os.name == 'nt', 'Windows does not expose Unix executable-mode changes')
    def test_provenance_binds_mode_only_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            subprocess.run(['git', 'init', str(repo)], check=True, capture_output=True)
            path = repo / 'tool'; path.write_bytes(b'unchanged bytes'); path.chmod(0o644)
            # provenance requires a real commit, not a fabricated source revision.
            subprocess.run(['git', '-C', str(repo), 'add', '.'], check=True)
            subprocess.run(['git', '-C', str(repo), '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-m', 'fixture'], check=True, capture_output=True)
            first = bundle.provenance(repo)
            path.chmod(0o755)
            second = bundle.provenance(repo)
            self.assertEqual(first['inputs']['tool']['sha256'], second['inputs']['tool']['sha256'])
            self.assertNotEqual(first['inputs']['tool']['mode'], second['inputs']['tool']['mode'])
            self.assertNotEqual(first['inputs_sha256'], second['inputs_sha256'])

    def test_flutter_generated_inputs_stay_lf_with_windows_git_checkout_policy(self):
        source = Path(__file__).resolve().parents[1]
        attributes = (source / '.gitattributes').read_text()
        paths = [line.split()[0] for line in attributes.splitlines() if line and not line.startswith('#')]
        self.assertEqual(len(paths), 7)
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            def git(*args):
                return subprocess.check_output(['git', '-c', 'user.email=fixture@example.invalid', '-c', 'user.name=Fixture', *args], cwd=repo, stderr=subprocess.DEVNULL)
            git('init'); git('config', 'core.autocrlf', 'true')
            (repo / '.gitattributes').write_text(attributes)
            original = {}
            for name in paths:
                path = repo / name; path.parent.mkdir(parents=True, exist_ok=True)
                original[name] = (source / name).read_bytes()
                self.assertNotIn(b'\r\n', original[name])
                path.write_bytes(original[name])
            git('add', '.'); git('commit', '-m', 'fixture')
            for name in paths: (repo / name).unlink()
            git('checkout', '--', '.')
            before = bundle.provenance(repo)
            for name in paths:
                self.assertEqual((repo / name).read_bytes(), original[name])
                (repo / name).write_bytes(original[name]) # Flutter's LF regeneration
            after = bundle.provenance(repo)
            self.assertEqual(before['inputs'], after['inputs'])
            self.assertFalse(after['source_dirty'])

    def test_command_launcher_uses_isolated_target_and_static_windows_crt(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            with patch.object(bundle.subprocess, 'run') as run:
                bundle.build_commands(repo, 'windows')
            commands = run.call_args_list
            self.assertEqual(len(commands), 2)
            self.assertIn('target-feature=+crt-static', commands[1].kwargs['env']['RUSTFLAGS'])
            self.assertIn(str(repo / 'companion/rust/target/command-launcher'), commands[1].args[0])
            self.assertIn('target-feature=+crt-static', commands[0].kwargs['env']['RUSTFLAGS'])

    def test_signed_macos_bundle_retains_sandbox_and_selected_executable_permission(self):
        keys = ['com.apple.security.app-sandbox', 'com.apple.security.files.user-selected.read-write', 'com.apple.security.files.user-selected.executable']
        for missing in [None, *keys]:
            values = {key: True for key in keys if key != missing}
            result = subprocess.CompletedProcess([], 0, plistlib.dumps(values), b'')
            with patch.object(bundle.subprocess, 'run', return_value=result):
                if missing is None: bundle.verify_macos_entitlements(Path('synthetic.app'))
                else:
                    with self.assertRaises(ValueError): bundle.verify_macos_entitlements(Path('synthetic.app'))

    def test_build_metadata_and_platform_commands_are_not_version_equality(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary) / 'source'; repo.mkdir()
            (repo / 'companion/rust/target/command-launcher/release').mkdir(parents=True)
            (repo / 'target/release').mkdir(parents=True)
            (repo / 'Cargo.toml').write_text('[package]\nversion="7.2.1"\n')
            (repo / 'companion/rust/Cargo.toml').write_text('[package]\nversion="0.1.0"\n')
            (repo / 'companion/pubspec.yaml').write_text('version: 0.1.0+1\n')
            root = Path(temporary) / 'bundle'; root.mkdir()
            for name in ['vaultwarden-cli', 'vw-access', 'vaultwarden-accessd', 'vaultwarden-access-exec']:
                p = repo / 'target/release' / name; p.write_bytes(b'synthetic'); p.chmod(0o755)
            p = repo / 'companion/rust/target/command-launcher/release/companion-command'; p.write_bytes(b'launcher'); p.chmod(0o755)
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
