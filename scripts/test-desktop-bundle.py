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
                machine = 'arm64' if platform == 'macos' else 'x86_64'
                with patch.object(bundle.shutil, 'which', return_value=resolved) as which, patch.object(bundle.subprocess, 'run') as run, patch.object(bundle.host_platform, 'machine', return_value=machine):
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
            repo = Path(temporary) / 'source'; repo.mkdir(exist_ok=True)
            (repo / 'companion/rust/target/command-launcher/release').mkdir(parents=True)
            (repo / 'target/release').mkdir(parents=True)
            (repo / 'Cargo.toml').write_text('[package]\nversion="7.2.1"\n')
            (repo / 'companion/rust/Cargo.toml').write_text('[package]\nversion="0.1.0"\n')
            (repo / 'companion/pubspec.yaml').write_text('version: 0.1.0+1\n')
            root = Path(temporary) / 'bundle'; root.mkdir(exist_ok=True)
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

    def synthetic_populate(self, temporary, platform, machine, env=None):
        """populate() over synthetic files; macOS signing/lipo calls are faked."""
        suffix = '.exe' if platform == 'windows' else ''
        repo = Path(temporary) / 'source'; repo.mkdir(exist_ok=True)
        (repo / 'companion/rust/target/command-launcher/release').mkdir(parents=True)
        (repo / 'target/release').mkdir(parents=True)
        (repo / 'Cargo.toml').write_text('[package]\nversion="7.2.1"\n')
        (repo / 'companion/rust/Cargo.toml').write_text('[package]\nversion="0.1.0"\n')
        (repo / 'companion/pubspec.yaml').write_text('version: 0.1.0+1\n')
        # Every protected binary exists in the cargo target: the bundle must
        # choose what to ship, not inherit whatever happens to be built.
        for name in ['vaultwarden-cli', 'vw-access', 'vaultwarden-accessd', 'vaultwarden-access-exec']:
            p = repo / 'target/release' / (name + suffix); p.write_bytes(b'synthetic ' + name.encode()); p.chmod(0o755)
        p = repo / 'companion/rust/target/command-launcher/release' / ('companion-command' + suffix); p.write_bytes(b'launcher'); p.chmod(0o755)
        root = Path(temporary) / 'bundle'; root.mkdir(exist_ok=True)
        runtime = {'macos': ['Contents/MacOS/companion_slice', 'Contents/Frameworks/libcompanion_core.dylib'],
                   'windows': ['companion_slice.exe', 'companion_core.dll'],
                   'linux': ['companion_slice', 'lib/libcompanion_core.so']}[platform]
        for name in runtime:
            p = root / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(b'runtime'); p.chmod(0o755)
        lipo = machine if platform == 'macos' else None
        def run(argv, *args, **kwargs):
            return subprocess.CompletedProcess(argv, 0, '', 'Signature=adhoc\n')
        source = {'revision': 'a' * 40, 'inputs_sha256': 'b' * 64}
        with patch.dict(os.environ, env or {}, clear=True), patch.object(bundle.host_platform, 'machine', return_value=machine), \
                patch.object(bundle.subprocess, 'run', side_effect=run) as fake_run, \
                patch.object(bundle.subprocess, 'check_output', return_value=f'{lipo}\n'), \
                patch.object(bundle, 'verify_macos_entitlements'):
            manifest = bundle.populate(repo, root, platform, source)
        return root, manifest, fake_run

    def test_macos_arm64_bundles_and_advertises_native_protected_commands(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, manifest, run = self.synthetic_populate(temporary, 'macos', 'arm64')
            helpers = root / 'Contents/Helpers'
            self.assertEqual(sorted(p.name for p in helpers.iterdir()), ['companion-command', 'vaultwarden-accessd', 'vaultwarden-cli', 'vw-access'])
            # The native provider does not use the Linux systemd helper.
            self.assertFalse((helpers / 'vaultwarden-access-exec').exists())
            self.assertEqual(manifest['architecture'], 'aarch64')
            self.assertEqual(manifest['commands'], {'vaultwarden-cli': 'Contents/Helpers/vaultwarden-cli', 'vw-access': 'Contents/Helpers/vw-access'})
            self.assertEqual(manifest['roles'], {'protected_requesting': True, 'desktop_approval': True, 'protected_provider': True, 'vault_cli': True})
            payloads = {entry['path']: entry for entry in manifest['payloads']}
            for name in ['vw-access', 'vaultwarden-accessd']:
                entry = payloads['Contents/Helpers/' + name]
                # A Windows host records executability by `.exe` suffix, not mode bits.
                if os.name != 'nt':
                    self.assertTrue(entry['executable'])
                self.assertEqual(entry['sha256'], bundle.artifact.digest(helpers / name))
            signed = [call.args[0][-1] for call in run.call_args_list if call.args[0][:4] == ['/usr/bin/codesign', '--force', '--sign', '-'] and len(call.args[0]) == 5]
            self.assertEqual(sorted(Path(p).name for p in signed), ['companion-command', 'vaultwarden-accessd', 'vaultwarden-cli', 'vw-access'])
            # A release job that promises arm64 accepts exactly this helper set,
            # and the archive name says arm64.
            bundle.check_expected_architecture(root, manifest, 'arm64')
            bundle.check_expected_architecture(root, manifest, 'aarch64')
            self.assertEqual(bundle.archive_architecture('macos', manifest['architecture']), 'arm64')
            # Intel macOS is not built at all: a job promising it is refused.
            with self.assertRaisesRegex(ValueError, 'Intel \\(x86_64\\) macOS is no longer supported'):
                bundle.check_expected_architecture(root, manifest, 'x86_64')
            (helpers / 'vaultwarden-accessd').unlink()
            with self.assertRaisesRegex(ValueError, 'bundled commands'):
                bundle.check_expected_architecture(root, manifest, 'arm64')
            (helpers / 'vaultwarden-accessd').write_bytes(b'replaced')
            with self.assertRaisesRegex(ValueError, 'damaged'):
                bundle.verify(root, manifest)

    def test_macos_developer_id_signing_happens_before_the_manifest_and_replaces_ad_hoc(self):
        import datetime
        events = []
        declared = {'com.apple.security.app-sandbox': True, 'com.apple.security.network.client': True,
                    'com.apple.security.files.user-selected.read-write': True, 'com.apple.security.files.user-selected.executable': True}
        profile = {'Platform': ['OSX'], 'TeamIdentifier': ['9884BZY594'], 'ProvisionsAllDevices': True,
                   'ExpirationDate': datetime.datetime(2044, 1, 1),
                   'Entitlements': {'com.apple.application-identifier': '9884BZY594.dev.vaultwarden.companionSlice',
                                    'com.apple.developer.team-identifier': '9884BZY594', 'keychain-access-groups': ['9884BZY594.*']}}
        signer = bundle.release_signing
        def prepare(temporary):
            repo = Path(temporary) / 'source'
            (repo / 'companion/macos/Runner').mkdir(parents=True)
            (repo / 'companion/macos/Runner/Release.entitlements').write_bytes(plistlib.dumps(declared))
            (Path(temporary) / 'bundle/Contents').mkdir(parents=True)
            (Path(temporary) / 'bundle/Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier': 'dev.vaultwarden.companionSlice'}))
        with tempfile.TemporaryDirectory() as temporary:
            source_profile = Path(temporary) / 'companion.provisionprofile'
            source_profile.write_bytes(b'profile bytes')
            prepare(temporary)
            env = {'MACOS_SIGNING_IDENTITY': 'A' * 40, 'MACOS_PROVISIONING_PROFILE': str(source_profile)}
            with patch.object(signer, 'entitlements_of', return_value={**declared, 'com.apple.security.get-task-allow': True}), \
                    patch.object(signer, 'read_profile', return_value=profile), \
                    patch.object(signer, 'sign_nested', side_effect=lambda root, s: events.append(('nested', (root / 'Contents/embedded.provisionprofile').exists(), (root / 'Contents/Resources/bundle.json').exists()))), \
                    patch.object(signer, 'sign_app', side_effect=lambda root, s, e: events.append(('app', e, (root / 'Contents/Resources/bundle.json').exists()))), \
                    patch.object(signer, 'verify', side_effect=lambda root, team, e: events.append(('verify', team, e))):
                root, manifest, run = self.synthetic_populate(temporary, 'macos', 'arm64', env)
            expected = {**declared, 'com.apple.application-identifier': '9884BZY594.dev.vaultwarden.companionSlice',
                        'com.apple.developer.team-identifier': '9884BZY594', 'keychain-access-groups': ['9884BZY594.dev.vaultwarden.companionSlice']}
            # Profile embedded and nested code signed before the manifest; the app sealed after it.
            self.assertEqual(events, [('nested', True, False), ('app', expected, True), ('verify', '9884BZY594', expected)])
            self.assertFalse([c for c in run.call_args_list if '--sign' in c.args[0] and '-' in c.args[0]])
            payloads = {entry['path']: entry['sha256'] for entry in manifest['payloads']}
            self.assertEqual(payloads['Contents/embedded.provisionprofile'], bundle.artifact.digest(source_profile))
            # A built app that is not Flutter's Release.entitlements is refused, not resealed.
            events.clear()
            with patch.object(signer, 'entitlements_of', return_value={**declared, 'com.apple.security.cs.allow-jit': True}), \
                    patch.object(signer, 'read_profile', return_value=profile), patch.object(signer, 'sign_nested') as nested:
                second = Path(temporary) / 'second'
                prepare(second)
                with self.assertRaisesRegex(ValueError, 'differ from Release.entitlements'):
                    self.synthetic_populate(str(second), 'macos', 'arm64', env)
            nested.assert_not_called()

    def test_archive_variant_follows_the_configured_signing(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(bundle.signing_variant('macos'), ('development', None, None))
        configured = {'MACOS_SIGNING_IDENTITY': 'A' * 40, 'MACOS_PROVISIONING_PROFILE': '/p'}
        with patch.dict(os.environ, configured, clear=True):
            self.assertEqual(bundle.signing_variant('macos')[0], 'signed')
            self.assertEqual(bundle.signing_variant('linux'), ('development', None, None))
        with patch.dict(os.environ, {**configured, 'MACOS_NOTARY_KEYCHAIN_PROFILE': 'vw'}, clear=True):
            variant, signing, notary = bundle.signing_variant('macos')
            self.assertEqual((variant, signing.team, notary.keychain_profile), ('notarized', '9884BZY594', 'vw'))

    def test_macos_intel_is_refused_at_every_stage(self):
        # Owner decision 2026-11-10: Intel (x86_64) macOS is no longer supported
        # or built. No stage may produce, name or accept an Intel macOS bundle.
        refused = 'Intel \\(x86_64\\) macOS is no longer supported'
        for machine in ['x86_64', 'i386']:
            with tempfile.TemporaryDirectory() as temporary:
                with self.assertRaisesRegex(ValueError, refused):
                    self.synthetic_populate(temporary, 'macos', machine)
                # Refused before anything was copied into the bundle.
                self.assertFalse((Path(temporary) / 'bundle/Contents/Helpers/vaultwarden-cli').exists())
            with tempfile.TemporaryDirectory() as temporary, patch.object(bundle.subprocess, 'run') as run, \
                    patch.object(bundle.host_platform, 'machine', return_value=machine):
                with self.assertRaisesRegex(ValueError, refused):
                    bundle.build_commands(Path(temporary), 'macos')
                run.assert_not_called()
            with tempfile.TemporaryDirectory() as temporary, patch.object(bundle.subprocess, 'run') as run, \
                    patch.object(bundle.shutil, 'which', return_value='/sdk/flutter'), \
                    patch.object(bundle.host_platform, 'machine', return_value=machine):
                with self.assertRaisesRegex(ValueError, refused):
                    bundle.build_app(Path(temporary), 'macos', Path(temporary))
                run.assert_not_called()
        with self.assertRaisesRegex(ValueError, refused):
            bundle.protected_commands('macos', 'x86_64')
        with self.assertRaisesRegex(ValueError, refused):
            bundle.archive_architecture('macos', 'x86_64')
        with tempfile.TemporaryDirectory() as temporary:
            root, manifest, _ = self.synthetic_populate(temporary, 'macos', 'arm64')
            for expected in ['x86_64', 'AMD64']:
                with self.assertRaisesRegex(ValueError, refused):
                    bundle.check_expected_architecture(root, manifest, expected)
            # A manifest claiming Intel macOS is refused even when the job expects it.
            with self.assertRaisesRegex(ValueError, refused):
                bundle.check_expected_architecture(root, dict(manifest, architecture='x86_64'), 'x86_64')
        # Only Intel *Mac* is dropped: Linux and Windows x86_64 stay supported.
        self.assertEqual(bundle.protected_commands('linux', 'x86_64'), ['vw-access', 'vaultwarden-accessd', 'vaultwarden-access-exec'])
        self.assertEqual(bundle.protected_commands('windows', 'x86_64'), [])

    def test_expected_architecture_is_optional_and_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, manifest, _ = self.synthetic_populate(temporary, 'linux', 'x86_64')
            # Optional for a local manual run, with a warning...
            with patch.dict(os.environ, {'CI': '', 'GITHUB_ACTIONS': ''}), patch('sys.stderr') as stderr:
                bundle.check_expected_architecture(root, manifest, '')
            self.assertIn('DESKTOP_EXPECTED_ARCHITECTURE', ''.join(call.args[0] for call in stderr.write.call_args_list))
            # ...but required in CI, so a job cannot drop the check by accident.
            for key in ['CI', 'GITHUB_ACTIONS']:
                with patch.dict(os.environ, {'CI': '', 'GITHUB_ACTIONS': '', key: 'true'}):
                    with self.assertRaisesRegex(ValueError, 'DESKTOP_EXPECTED_ARCHITECTURE is required'):
                        bundle.check_expected_architecture(root, manifest, '')
            bundle.check_expected_architecture(root, manifest, 'x86_64')
            self.assertIsNone(bundle.archive_architecture('linux', 'x86_64'))
            self.assertIsNone(bundle.archive_architecture('windows', 'x86_64'))
            with self.assertRaisesRegex(ValueError, 'unsupported expected architecture'):
                bundle.check_expected_architecture(root, manifest, 'riscv64')
            manifest = dict(manifest, commands={'vaultwarden-cli': 'commands/vaultwarden-cli'})
            with self.assertRaisesRegex(ValueError, 'advertised protected commands'):
                bundle.check_expected_architecture(root, manifest, 'x86_64')

    def test_linux_and_windows_protected_commands_are_unchanged(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, manifest, _ = self.synthetic_populate(temporary, 'linux', 'x86_64')
            self.assertEqual(sorted(p.name for p in (root / 'commands').iterdir()), ['companion-command', 'vaultwarden-access-exec', 'vaultwarden-accessd', 'vaultwarden-cli', 'vw-access'])
            self.assertEqual(set(manifest['commands']), {'vaultwarden-cli', 'vw-access'})
            self.assertTrue(manifest['roles']['protected_requesting'] and manifest['roles']['protected_provider'])
        with tempfile.TemporaryDirectory() as temporary:
            root, manifest, _ = self.synthetic_populate(temporary, 'windows', 'AMD64')
            self.assertEqual(sorted(p.name for p in (root / 'commands').iterdir()), ['companion-command.exe', 'vaultwarden-cli.exe'])
            self.assertEqual(manifest['commands'], {'vaultwarden-cli': 'commands/vaultwarden-cli.exe'})
            self.assertEqual(manifest['architecture'], 'x86_64')
            self.assertEqual(manifest['roles'], {'protected_requesting': False, 'desktop_approval': False, 'protected_provider': False, 'vault_cli': True})

    def test_command_build_selects_protected_binaries_by_platform_and_architecture(self):
        cases = [('linux', 'x86_64', ['vaultwarden-cli', 'vw-access', 'vaultwarden-accessd', 'vaultwarden-access-exec']),
                 ('macos', 'arm64', ['vaultwarden-cli', 'vw-access', 'vaultwarden-accessd']),
                 ('windows', 'AMD64', ['vaultwarden-cli'])]
        for platform, machine, expected in cases:
            with tempfile.TemporaryDirectory() as temporary, patch.object(bundle.subprocess, 'run') as run, patch.object(bundle.host_platform, 'machine', return_value=machine):
                self.assertEqual(bundle.build_commands(Path(temporary), platform), expected)
                argv = run.call_args_list[0].args[0]
                self.assertEqual([argv[i + 1] for i, item in enumerate(argv) if item == '--bin'], expected)

if __name__ == '__main__':
    unittest.main()
