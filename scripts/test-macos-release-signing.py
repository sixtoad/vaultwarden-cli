#!/usr/bin/env python3
"""Developer ID signing/notarization tests (#62). Fake tools only: no identity,
keychain, network or Apple service is used."""
import datetime
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import re
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


signing = load('release_signing', 'macos-release-signing.py')
TEAM = signing.RELEASE_TEAM_ID
BUNDLE_ID = 'dev.vaultwarden.companionSlice'
MACHO = b'\xcf\xfa\xed\xfe' + b'\0' * 60


def profile(**changes):
    value = {
        'Platform': ['OSX'], 'TeamIdentifier': [TEAM], 'ProvisionsAllDevices': True,
        'ExpirationDate': datetime.datetime(2044, 10, 15, 11, 6, 52),
        'Entitlements': {'com.apple.application-identifier': f'{TEAM}.{BUNDLE_ID}',
                         'com.apple.developer.team-identifier': TEAM, 'keychain-access-groups': [f'{TEAM}.*']},
    }
    value.update(changes)
    return value


def write(path, data=MACHO, mode=0o755):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)
    return path


def app_tree(root):
    app = root / 'companion_slice.app'
    write(app / 'Contents/MacOS/companion_slice')
    for name in ['vw-access', 'vaultwarden-accessd', 'vaultwarden-cli', 'companion-command']:
        write(app / 'Contents/Helpers' / name)
    write(app / 'Contents/Frameworks/libcompanion_core.dylib')
    for name in ['FlutterMacOS', 'App']:
        framework = app / f'Contents/Frameworks/{name}.framework'
        write(framework / f'Versions/A/{name}')
        write(framework / 'Versions/A/Resources/Info.plist', b'<plist/>', 0o644)
        (framework / 'Versions/Current').symlink_to('A')
        (framework / name).symlink_to(f'Versions/Current/{name}')
    write(app / 'Contents/Frameworks/FlutterMacOS.framework/Versions/A/Helpers/nested', MACHO)
    write(app / 'Contents/Resources/data.bin', b'not code', 0o644)
    (app / 'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier': BUNDLE_ID}))
    return app


class FakeTools:
    """Records argv; answers codesign/notarytool like the real tools would."""

    def __init__(self, team=TEAM, runtime=True, helper_entitlements=None, app_entitlements=None,
                 status='Accepted', spctl='source=Notarized Developer ID', failing_verify=()):
        self.calls, self.team, self.runtime = [], team, runtime
        self.helper_entitlements, self.app_entitlements = helper_entitlements, app_entitlements
        self.status, self.spctl, self.failing_verify = status, spctl, failing_verify

    def __call__(self, argv, capture_output=False, text=False, check=False, **kwargs):
        self.calls.append(list(argv))
        out, err, code = '', '', 0
        if argv[0] == signing.CODESIGN and argv[1] == '--verify':
            code = 1 if any(argv[-1].endswith(name) for name in self.failing_verify) else 0
        elif argv[0] == signing.CODESIGN and argv[1:3] == ['-d', '--verbose=2']:
            flags = '0x10000(runtime)' if self.runtime else '0x0(none)'
            err = f'Identifier=x\nCodeDirectory v=20500 size=1 flags={flags} hashes=1+1\nTimestamp=1 Jan 2026\nTeamIdentifier={self.team}\n'
        elif argv[0] == signing.CODESIGN and argv[1:3] == ['-d', '--entitlements']:
            value = self.app_entitlements if argv[-1].endswith('.app') else self.helper_entitlements
            out = plistlib.dumps(value) if value else b''
        elif argv[:3] == ['/usr/bin/xcrun', 'notarytool', 'submit']:
            out = json.dumps({'id': 'submission-1', 'status': self.status})
        elif argv[:3] == ['/usr/bin/xcrun', 'notarytool', 'log']:
            out = '{"issues": ["synthetic"]}'
        elif argv[0] == '/usr/sbin/spctl':
            err = f'{argv[-1]}: accepted\n{self.spctl}\n'
            code = 0 if 'Notarized' in self.spctl else 3
        if check and code:
            raise subprocess.CalledProcessError(code, argv)
        if not text and isinstance(out, str):
            out = out.encode()
        return subprocess.CompletedProcess(argv, code, out, err)


class ConfigurationTests(unittest.TestCase):
    def test_no_identity_is_the_development_build_and_a_lone_profile_is_refused(self):
        self.assertIsNone(signing.signing_from_env({}))
        with self.assertRaisesRegex(signing.SigningError, 'without MACOS_SIGNING_IDENTITY'):
            signing.signing_from_env({'MACOS_PROVISIONING_PROFILE': '/p'})

    def test_identity_must_be_developer_id_application_of_the_team(self):
        good = {'MACOS_SIGNING_IDENTITY': f'Developer ID Application: Example ({TEAM})', 'MACOS_PROVISIONING_PROFILE': '/p'}
        value = signing.signing_from_env(good)
        self.assertEqual((value.team, value.profile, value.keychain), (TEAM, Path('/p'), None))
        self.assertEqual(signing.signing_from_env({**good, 'MACOS_SIGNING_IDENTITY': 'A' * 40, 'MACOS_SIGNING_KEYCHAIN': '/k'}).keychain, Path('/k'))
        for identity in [f'Apple Development: Example ({TEAM})', 'Developer ID Application: Example (ABCDE12345)', '-',
                         f'3rd Party Mac Developer Application: Example ({TEAM})']:
            with self.assertRaisesRegex(signing.SigningError, 'Developer ID Application'):
                signing.signing_from_env({**good, 'MACOS_SIGNING_IDENTITY': identity})
        with self.assertRaisesRegex(signing.SigningError, 'PROVISIONING_PROFILE is required'):
            signing.signing_from_env({'MACOS_SIGNING_IDENTITY': good['MACOS_SIGNING_IDENTITY']})
        with self.assertRaisesRegex(signing.SigningError, 'MACOS_TEAM_ID'):
            signing.signing_from_env({**good, 'MACOS_TEAM_ID': 'team'})

    def test_notary_is_a_keychain_profile_or_a_complete_api_key(self):
        self.assertIsNone(signing.notary_from_env({}))
        self.assertEqual(signing.notary_from_env({'MACOS_NOTARY_KEYCHAIN_PROFILE': 'vw'}).arguments(), ['--keychain-profile', 'vw'])
        with tempfile.TemporaryDirectory() as temporary:
            key = write(Path(temporary) / 'AuthKey.p8', b'synthetic', 0o600)
            env = {'MACOS_NOTARY_KEY_PATH': str(key), 'MACOS_NOTARY_KEY_ID': 'KEY', 'MACOS_NOTARY_ISSUER_ID': 'ISSUER'}
            self.assertEqual(signing.notary_from_env(env).arguments(), ['--key', str(key), '--key-id', 'KEY', '--issuer', 'ISSUER'])
            with self.assertRaisesRegex(signing.SigningError, 'not both'):
                signing.notary_from_env({**env, 'MACOS_NOTARY_KEYCHAIN_PROFILE': 'vw'})
            for missing in env:
                with self.assertRaisesRegex(signing.SigningError, 'needs'):
                    signing.notary_from_env({k: v for k, v in env.items() if k != missing})
            with self.assertRaisesRegex(signing.SigningError, 'not name a file'):
                signing.notary_from_env({**env, 'MACOS_NOTARY_KEY_PATH': str(key) + '.missing'})

    def test_release_can_require_signing_and_notarization(self):
        signed = {'MACOS_SIGNING_IDENTITY': 'A' * 40, 'MACOS_PROVISIONING_PROFILE': '/p'}
        full = {**signed, 'MACOS_NOTARY_KEYCHAIN_PROFILE': 'vw'}
        self.assertEqual(signing.configured({}), (None, None))
        self.assertIsNone(signing.configured(signed)[1])
        self.assertEqual(signing.configured({**full, 'MACOS_REQUIRE_DEVELOPER_ID': 'true'})[1].keychain_profile, 'vw')
        for env in [{}, signed]:
            with self.assertRaisesRegex(signing.SigningError, 'must both be configured'):
                signing.configured({**env, 'MACOS_REQUIRE_DEVELOPER_ID': 'true'})
        with self.assertRaisesRegex(signing.SigningError, 'without Developer ID signing'):
            signing.configured({'MACOS_NOTARY_KEYCHAIN_PROFILE': 'vw'})

    def test_status_never_prints_secret_values(self):
        env = {'MACOS_SIGNING_IDENTITY': 'B' * 40, 'MACOS_PROVISIONING_PROFILE': '/secret/dir/companion.provisionprofile',
               'MACOS_SIGNING_KEYCHAIN': '/secret/k.keychain-db', 'MACOS_NOTARY_KEYCHAIN_PROFILE': 'secret-profile-name'}
        text = signing.describe(env)
        for value in ['B' * 40, '/secret/', 'secret-profile-name']:
            self.assertNotIn(value, text)
        self.assertIn('keychain profile', text)
        self.assertIn('NOT configured', signing.describe({k: v for k, v in env.items() if 'NOTARY' not in k}))
        self.assertIn('development build', signing.describe({}))


class RequirementTests(unittest.TestCase):
    def test_release_requirement_matches_the_provider_and_the_installer(self):
        requirement = signing.designated_requirement(TEAM)
        source = (HERE.parent / 'src/adapters/native/image.rs').read_text()
        self.assertEqual(re.search(r'pub\(crate\) const RELEASE_TEAM_ID: &str = "([A-Z0-9]{10})";', source).group(1), TEAM)
        self.assertEqual(re.search(r'const DEVELOPER_ID: &str = "([^"]+)";', source).group(1), signing.DEVELOPER_ID)
        if os.name != 'nt':  # the installer is POSIX-only (fcntl)
            installer = load('installer', 'macos-provider-install.py')
            self.assertEqual(installer.designated_requirement(TEAM), '=' + requirement)
        self.assertTrue(requirement.endswith(f'certificate leaf[subject.OU] = "{TEAM}"'))
        with self.assertRaises(signing.SigningError):
            signing.designated_requirement('9884bzy594')


class ProfileTests(unittest.TestCase):
    def test_developer_id_profile_of_the_app_is_accepted(self):
        entitlements = signing.check_profile(profile(), TEAM, BUNDLE_ID)
        self.assertEqual(entitlements['keychain-access-groups'], [f'{TEAM}.*'])

    def test_wrong_profiles_are_refused_naming_the_reason(self):
        other = profile()['Entitlements'] | {'com.apple.application-identifier': f'{TEAM}.dev.vaultwarden.ApprovalCompanion.ProviderBridge'}
        cases = [
            (profile(Platform=['iOS']), 'not a macOS profile'),
            (profile(TeamIdentifier=['ABCDE12345']), 'not for team'),
            (profile(ProvisionedDevices=['device']), 'not a Developer ID profile'),
            (profile(ProvisionsAllDevices=False), 'not a Developer ID profile'),
            (profile(ExpirationDate=datetime.datetime(2020, 1, 1)), 'expired'),
            (profile(Entitlements=other), 'ProviderBridge, not'),
            (profile(Entitlements=profile()['Entitlements'] | {'get-task-allow': True}), 'get-task-allow'),
            (profile(Entitlements=profile()['Entitlements'] | {'com.apple.developer.team-identifier': 'ABCDE12345'}), 'team entitlement'),
        ]
        for value, message in cases:
            with self.assertRaisesRegex(signing.SigningError, message):
                signing.check_profile(value, TEAM, BUNDLE_ID)

    def test_profile_is_decoded_with_security_cms(self):
        calls = []

        def run(argv, **kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, plistlib.dumps({'Platform': ['OSX']}), b'')
        self.assertEqual(signing.read_profile(Path('/p'), run), {'Platform': ['OSX']})
        self.assertEqual(calls, [['/usr/bin/security', 'cms', '-D', '-i', str(Path('/p'))]])
        with self.assertRaisesRegex(signing.SigningError, 'cannot decode'):
            signing.read_profile(Path('/p'), lambda argv, **kwargs: subprocess.CompletedProcess(argv, 1, b'', b''))

    def test_app_entitlements_are_the_declared_sandbox_plus_the_granted_identity(self):
        declared = {'com.apple.security.app-sandbox': True, 'com.apple.security.network.client': True}
        value = signing.app_entitlements(declared, TEAM, BUNDLE_ID, profile()['Entitlements'])
        self.assertEqual(value, {**declared, 'com.apple.application-identifier': f'{TEAM}.{BUNDLE_ID}',
                                 'com.apple.developer.team-identifier': TEAM, 'keychain-access-groups': [f'{TEAM}.{BUNDLE_ID}']})
        exact = profile()['Entitlements'] | {'keychain-access-groups': [f'{TEAM}.{BUNDLE_ID}']}
        self.assertEqual(signing.app_entitlements(declared, TEAM, BUNDLE_ID, exact)['keychain-access-groups'], [f'{TEAM}.{BUNDLE_ID}'])
        with self.assertRaisesRegex(signing.SigningError, 'does not grant keychain group'):
            signing.app_entitlements(declared, TEAM, BUNDLE_ID, profile()['Entitlements'] | {'keychain-access-groups': ['ABCDE12345.*']})
        with self.assertRaisesRegex(signing.SigningError, 'restricted'):
            signing.app_entitlements({**declared, 'keychain-access-groups': ['x']}, TEAM, BUNDLE_ID, profile()['Entitlements'])
        with self.assertRaisesRegex(signing.SigningError, 'forbidden'):
            signing.app_entitlements({**declared, 'com.apple.security.cs.allow-jit': True}, TEAM, BUNDLE_ID, profile()['Entitlements'])


@unittest.skipIf(os.name == 'nt', 'POSIX bundle layout (symbolic links, modes) and bash')
class SigningTests(unittest.TestCase):
    def test_nested_code_is_signed_inside_out_and_the_app_is_not(self):
        with tempfile.TemporaryDirectory() as temporary:
            app = app_tree(Path(temporary))
            order = [p.relative_to(app).as_posix() for p in signing.signing_order(app)]
            self.assertEqual(order, [
                'Contents/Frameworks/FlutterMacOS.framework/Versions/A/Helpers/nested',
                'Contents/Frameworks/libcompanion_core.dylib',
                'Contents/Helpers/companion-command', 'Contents/Helpers/vaultwarden-accessd',
                'Contents/Helpers/vaultwarden-cli', 'Contents/Helpers/vw-access',
                'Contents/Frameworks/App.framework', 'Contents/Frameworks/FlutterMacOS.framework',
            ])

    def test_java_class_files_are_not_code_and_nested_bundles_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            app = app_tree(Path(temporary))
            write(app / 'Contents/Resources/Example.class', b'\xca\xfe\xba\xbe\x00\x00\x00\x34' + b'\0' * 32, 0o644)
            write(app / 'Contents/Resources/fat', b'\xca\xfe\xba\xbe\x00\x00\x00\x02' + b'\0' * 32)
            names = [p.name for p in signing.signing_order(app)]
            self.assertNotIn('Example.class', names)
            self.assertIn('fat', names)
            write(app / 'Contents/Library/LoginItems/Helper.app/Contents/MacOS/Helper')
            with self.assertRaisesRegex(signing.SigningError, 'nested bundles'):
                signing.signing_order(app)

    def test_hardened_runtime_timestamp_and_no_entitlements_for_nested_code(self):
        with tempfile.TemporaryDirectory() as temporary:
            app = app_tree(Path(temporary))
            tools = FakeTools()
            config = signing.Signing('A' * 40, TEAM, Path('/p'), Path('/k.keychain-db'))
            signing.sign_nested(app, config, tools)
            for call in tools.calls:
                self.assertEqual(call[:9], [signing.CODESIGN, '--force', '--sign', 'A' * 40, '--options', 'runtime', '--timestamp', '--keychain', '/k.keychain-db'])
                self.assertNotIn('--entitlements', call)
            helpers = {Path(c[-1]).name: c[c.index('--identifier') + 1] for c in tools.calls if '--identifier' in c}
            self.assertEqual(helpers, {name: f'dev.vaultwarden.{name}' for name in ['companion-command', 'vaultwarden-accessd', 'vaultwarden-cli', 'vw-access']})
            tools.calls.clear()
            signing.sign_app(app, config, {'com.apple.security.app-sandbox': True}, tools)
            (call,) = tools.calls
            self.assertEqual((call[-3], call[-1]), ('--entitlements', str(app)))

    def test_profile_is_checked_then_embedded(self):
        with tempfile.TemporaryDirectory() as temporary:
            app = app_tree(Path(temporary))
            source = write(Path(temporary) / 'companion.provisionprofile', b'signed profile bytes', 0o600)
            config = signing.Signing('A' * 40, TEAM, source)
            run = lambda argv, **kwargs: subprocess.CompletedProcess(argv, 0, plistlib.dumps(profile()), b'')
            granted = signing.embed_profile(app, config, signing.bundle_identifier(app), run)
            self.assertEqual(granted['com.apple.application-identifier'], f'{TEAM}.{BUNDLE_ID}')
            self.assertEqual((app / signing.PROFILE_NAME).read_bytes(), b'signed profile bytes')
            (app / signing.PROFILE_NAME).unlink()
            bad = lambda argv, **kwargs: subprocess.CompletedProcess(argv, 0, plistlib.dumps(profile(TeamIdentifier=['ABCDE12345'])), b'')
            with self.assertRaises(signing.SigningError):
                signing.embed_profile(app, config, BUNDLE_ID, bad)
            self.assertFalse((app / signing.PROFILE_NAME).exists())


@unittest.skipIf(os.name == 'nt', 'POSIX bundle layout (symbolic links, modes) and bash')
class VerificationTests(unittest.TestCase):
    expected = {'com.apple.security.app-sandbox': True, 'keychain-access-groups': [f'{TEAM}.{BUNDLE_ID}']}

    def verify(self, **tools):
        with tempfile.TemporaryDirectory() as temporary:
            app = app_tree(Path(temporary))
            write(app / signing.PROFILE_NAME, b'profile', 0o644)
            fake = FakeTools(**{'app_entitlements': self.expected, **tools})
            signing.verify(app, TEAM, self.expected, fake)
            return fake

    def test_release_bundle_verifies_every_component_against_the_team_requirement(self):
        tools = self.verify()
        requirement = '=' + signing.designated_requirement(TEAM)
        deep = [c for c in tools.calls if '--deep' in c]
        self.assertEqual(len(deep), 1)
        self.assertEqual(deep[0][1:6], ['--verify', '--deep', '--strict', '-R', requirement])
        verified = {Path(c[-1]).name for c in tools.calls if c[1:3] == ['--verify', '--strict']}
        self.assertTrue({'vw-access', 'vaultwarden-accessd', 'libcompanion_core.dylib', 'FlutterMacOS.framework', 'companion_slice.app'} <= verified)

    def test_development_or_foreign_signatures_and_weakened_components_are_refused(self):
        cases = [
            ({'team': 'ABCDE12345'}, 'another team'),
            ({'runtime': False}, 'hardened runtime'),
            ({'helper_entitlements': {'com.apple.security.get-task-allow': True}}, 'forbidden entitlement'),
            ({'helper_entitlements': {'com.apple.security.app-sandbox': True}}, 'no entitlements'),
            ({'app_entitlements': {**self.expected, 'com.apple.security.network.server': True}}, 'differ from the minimum'),
            ({'failing_verify': ('vaultwarden-accessd',)}, 'not signed by Developer ID'),
            ({'failing_verify': ('companion_slice.app',)}, 'fails Developer ID verification'),
        ]
        for tools, message in cases:
            with self.subTest(message), self.assertRaisesRegex(signing.SigningError, message):
                self.verify(**tools)

    def test_missing_embedded_profile_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            app = app_tree(Path(temporary))
            with self.assertRaisesRegex(signing.SigningError, 'embedded provisioning profile'):
                signing.verify(app, TEAM, self.expected, FakeTools(app_entitlements=self.expected))


@unittest.skipIf(os.name == 'nt', 'POSIX bundle layout (symbolic links, modes) and bash')
class NotarizationTests(unittest.TestCase):
    def notarize(self, **tools):
        with tempfile.TemporaryDirectory() as temporary:
            app = app_tree(Path(temporary))
            fake = FakeTools(**tools)
            work = Path(temporary) / 'work'
            try:
                return fake, signing.notarize(app, signing.Notary(keychain_profile='vw'), work, fake), sorted(p.name for p in work.iterdir())
            except signing.SigningError as error:
                return fake, error, sorted(p.name for p in work.iterdir())

    def test_accepted_submission_is_stapled_validated_and_assessed(self):
        tools, identifier, files = self.notarize()
        self.assertEqual(identifier, 'submission-1')
        self.assertEqual([c[:3] for c in tools.calls], [
            ['/usr/bin/ditto', '-c', '-k'], ['/usr/bin/xcrun', 'notarytool', 'submit'],
            ['/usr/bin/xcrun', 'stapler', 'staple'], ['/usr/bin/xcrun', 'stapler', 'validate'],
            ['/usr/sbin/spctl', '--assess', '--type']])
        submit = tools.calls[1]
        self.assertIn('--wait', submit)
        self.assertEqual(submit[submit.index('--keychain-profile') + 1], 'vw')
        self.assertEqual(files, ['notarization-submission.json'])

    def test_rejected_submission_keeps_the_log_and_staples_nothing(self):
        tools, error, files = self.notarize(status='Invalid')
        self.assertIsInstance(error, signing.SigningError)
        self.assertIn("'Invalid'", str(error))
        self.assertIn(['/usr/bin/xcrun', 'notarytool', 'log', 'submission-1', '--keychain-profile', 'vw'], tools.calls)
        self.assertFalse(any('stapler' in c for c in tools.calls))
        self.assertIn('notarization-log.json', files)

    def test_gatekeeper_must_see_a_notarized_developer_id(self):
        _, error, _ = self.notarize(spctl='source=Unnotarized Developer ID')
        self.assertIsInstance(error, signing.SigningError)
        self.assertIn('Gatekeeper', str(error))



@unittest.skipIf(os.name == 'nt', 'POSIX bundle layout (symbolic links, modes) and bash')
class CiSetupTests(unittest.TestCase):
    """Only the paths that stop before any keychain command run here."""

    def run_setup(self, **secrets):
        with tempfile.TemporaryDirectory() as temporary:
            env_file = Path(temporary) / 'github-env'
            env_file.write_text('')
            env = {'PATH': '/usr/bin:/bin', 'GITHUB_ACTIONS': 'true', 'RUNNER_TEMP': temporary, 'GITHUB_ENV': str(env_file), **secrets}
            result = subprocess.run(['/bin/bash', str(HERE / 'ci-macos-signing.sh'), 'setup'], env=env, capture_output=True, text=True, timeout=60)
            return result, env_file.read_text(), sorted(p.name for p in Path(temporary).iterdir())

    def test_absent_secrets_skip_signing_with_a_notice(self):
        result, exported, files = self.run_setup()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('::notice::Developer ID signing secrets are not set', result.stdout)
        self.assertEqual((exported, files), ('', ['github-env']))
        result, exported, _ = self.run_setup(APPLE_NOTARY_API_KEY_ID='KEY')
        self.assertEqual(result.returncode, 0)
        self.assertIn('notarization skipped', result.stdout)
        self.assertEqual(exported, '')

    def test_partial_secrets_fail_before_touching_a_keychain(self):
        partial = [
            {'MACOS_DEVELOPER_ID_P12_BASE64': 'c2VjcmV0'},
            {'MACOS_DEVELOPER_ID_P12_BASE64': 'c2VjcmV0', 'MACOS_DEVELOPER_ID_P12_PASSWORD': 'pw'},
            {'MACOS_DEVELOPER_ID_P12_BASE64': 'c2VjcmV0', 'MACOS_DEVELOPER_ID_P12_PASSWORD': 'pw', 'MACOS_COMPANION_PROFILE_BASE64': 'cA==',
             'APPLE_NOTARY_API_KEY_ID': 'Z9SYNTH42'},
        ]
        for secrets in partial:
            result, exported, files = self.run_setup(**secrets)
            self.assertEqual(result.returncode, 1, secrets)
            self.assertIn('::error::set all of', result.stdout)
            self.assertEqual((exported, files), ('', ['github-env']))
            for value in secrets.values():
                self.assertNotIn(value, result.stdout + result.stderr)

    def test_required_developer_id_fails_without_every_secret(self):
        result, exported, files = self.run_setup(MACOS_REQUIRE_DEVELOPER_ID='true')
        self.assertEqual(result.returncode, 1)
        self.assertIn('all six', result.stdout)
        self.assertEqual((exported, files), ('', ['github-env']))

    def test_refuses_outside_github_actions(self):
        result = subprocess.run(['/bin/bash', str(HERE / 'ci-macos-signing.sh'), 'setup'], env={'PATH': '/usr/bin:/bin'}, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 2)
        self.assertIn('only in GitHub Actions', result.stderr)


if __name__ == '__main__':
    unittest.main()
