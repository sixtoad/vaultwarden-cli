#!/usr/bin/env python3
"""Installer-plan generator tests. All filesystem work uses temporary roots."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('plan', Path(__file__).with_name('macos-provider-plan.py'))
plan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plan)

INPUTS = {
    'version': '0.5.4',
    'provider_account': '_vwaccess',
    'provider_group': '_vwaccess',
    'provider_uid': '491',
    'provider_uuid': '0123456789abcdef0123456789abcdef',
    'operator_uid': '501',
    'operator_uuid': 'fedcba9876543210fedcba9876543210',
    'human_gid': '492',
    'agent_gid': '493',
}


def argv(output, **overrides):
    values = dict(INPUTS, **overrides)
    result = ['--output', str(output)]
    for key, value in values.items():
        # --flag=value: values such as '-1' must reach validation, not argparse.
        result.append('--' + key.replace('_', '-') + '=' + value)
    return result


def tree(root):
    return sorted((p.relative_to(root).as_posix(), p.read_bytes() if p.is_file() else None) for p in root.rglob('*'))


def quiet(function, *args):
    with contextlib.redirect_stderr(io.StringIO()) as err, contextlib.redirect_stdout(io.StringIO()):
        return function(*args), err.getvalue()


class PlanTests(unittest.TestCase):
    def test_happy_path_resolves_both_templates_and_keeps_security_keys(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'plan'
            code, _ = quiet(plan.main, argv(output))
            self.assertEqual(code, 0)
            self.assertEqual(sorted(p.name for p in output.iterdir()), ['com.cantolla.vaultwarden-accessd.plist', 'native-identities.json', 'plan.json'])
            for path in output.iterdir():
                self.assertNotRegex(path.read_text(), r'@[A-Za-z0-9_]+@')
            launchd = plistlib.loads((output / 'com.cantolla.vaultwarden-accessd.plist').read_bytes())
            self.assertIs(launchd['AbandonProcessGroup'], True)
            self.assertEqual(launchd['SoftResourceLimits'], {'Core': 0})
            self.assertEqual(launchd['HardResourceLimits'], {'Core': 0})
            self.assertEqual(launchd['StandardOutPath'], '/dev/null')
            self.assertEqual(launchd['StandardErrorPath'], '/dev/null')
            self.assertEqual(launchd['UserName'], '_vwaccess')
            self.assertEqual(launchd['GroupName'], '_vwaccess')
            self.assertEqual(launchd['ProgramArguments'][0], '/Library/VaultwardenAccess/versions/0.5.4/vaultwarden-accessd')
            gid = launchd['ProgramArguments'].index('--agent-socket-gid')
            self.assertEqual(launchd['ProgramArguments'][gid + 1], '493')
            identities = json.loads((output / 'native-identities.json').read_text())
            self.assertEqual(identities, {
                'provider_uid': 491, 'provider_uuid': INPUTS['provider_uuid'],
                'operator_uid': 501, 'operator_uuid': INPUTS['operator_uuid'],
                'human_gid': 492, 'agent_gid': 493,
                'human_socket_dir': '/Library/VaultwardenAccess/run/human',
                'ssh_runtime_dir': '/Library/VaultwardenAccess/run/ssh',
            })
            document = json.loads((output / 'plan.json').read_text())
            self.assertIs(document['installs'], False)
            files = {entry['destination']: entry for entry in document['files']}
            self.assertEqual(files['/Library/VaultwardenAccess/versions/0.5.4/vaultwarden-accessd']['source'], 'bundle:Contents/Helpers/vaultwarden-accessd')
            self.assertEqual(files['/Library/LaunchDaemons/com.cantolla.vaultwarden-accessd.plist']['sha256'],
                             hashlib.sha256((output / 'com.cantolla.vaultwarden-accessd.plist').read_bytes()).hexdigest())

    def test_resolution_is_deterministic(self):
        values = plan.validate_inputs(dict(INPUTS))
        self.assertEqual(plan.build(values), plan.build(values))
        with tempfile.TemporaryDirectory() as temporary:
            first, second = Path(temporary) / 'a', Path(temporary) / 'b'
            quiet(plan.main, argv(first)); quiet(plan.main, argv(second))
            self.assertEqual(tree(first), tree(second))

    def test_every_invalid_input_is_rejected_before_any_write(self):
        invalid = {
            'version': ['', '0.5', '0.5.4.1', 'v0.5.4', '00.5.4', '0.5.4+build', '0.5.4-', '../0.5.4', '0.5.4/x', '0.5.4 '],
            'provider_account': ['', 'Root', 'root', '1abc', 'a' * 33, 'a b', 'a/b', 'a<b', 'a$', '-x', 'ä'],
            'provider_group': ['', 'wheel', 'Staff', 'g:1', 'a' * 33],
            'provider_uid': ['', '0', '-1', '+5', '05', '1.0', 'x', '4294967295', '99999999999', ' 5', '0x10'],
            'operator_uid': ['0', 'abc', '4294967296'],
            'human_gid': ['0', '012', '-3'],
            'agent_gid': ['0', '1e3'],
            'provider_uuid': ['', '0' * 32, '0123456789ABCDEF0123456789ABCDEF', '01234567-89ab-cdef-0123-456789abcdef', 'g' * 32, 'a' * 31, 'a' * 33],
            'operator_uuid': ['0123456789abcdef0123456789abcdeF', 'z' * 32],
        }
        with tempfile.TemporaryDirectory() as temporary:
            for key, values in invalid.items():
                for value in values:
                    with self.subTest(key=key, value=value):
                        output = Path(temporary) / 'out'
                        with self.assertRaises(plan.PlanError):
                            plan.validate_inputs(dict(INPUTS, **{key: value}))
                        code, err = quiet(plan.main, argv(output, **{key: value}))
                        self.assertEqual(code, 2)
                        self.assertIn('macos-provider-plan:', err)
                        self.assertFalse(output.exists())

    def test_relationships_between_inputs_are_enforced(self):
        for overrides in [{'operator_uid': INPUTS['provider_uid']},
                          {'operator_uuid': INPUTS['provider_uuid']},
                          {'agent_gid': INPUTS['human_gid']}]:
            with self.subTest(overrides=overrides), self.assertRaises(plan.PlanError):
                plan.validate_inputs(dict(INPUTS, **overrides))
        with self.assertRaises(plan.PlanError):
            plan.validate_inputs({k: v for k, v in INPUTS.items() if k != 'agent_gid'})
        with self.assertRaises(plan.PlanError):
            plan.validate_inputs(dict(INPUTS, extra='1'))

    def test_unresolved_placeholders_are_rejected(self):
        values = plan.validate_inputs(dict(INPUTS))
        source = plan.TEMPLATES
        with tempfile.TemporaryDirectory() as temporary:
            templates = Path(temporary)
            for name in [plan.PLIST_TEMPLATE, plan.IDENTITIES_TEMPLATE]:
                shutil.copy(source / name, templates / name)
            launchd = (templates / plan.PLIST_TEMPLATE).read_text()
            (templates / plan.PLIST_TEMPLATE).write_text(launchd.replace('<string>127.0.0.1:8443</string>', '<string>@LISTEN_ADDRESS@</string>'))
            with self.assertRaisesRegex(plan.PlanError, '@LISTEN_ADDRESS@'):
                plan.build(values, templates)
            shutil.copy(source / plan.PLIST_TEMPLATE, templates / plan.PLIST_TEMPLATE)
            identities = json.loads((templates / plan.IDENTITIES_TEMPLATE).read_text())
            identities['ssh_runtime_dir'] = '@SSH_RUNTIME_DIR@'
            (templates / plan.IDENTITIES_TEMPLATE).write_text(json.dumps(identities))
            with self.assertRaisesRegex(plan.PlanError, '@SSH_RUNTIME_DIR@'):
                plan.build(values, templates)
            # A renamed placeholder (template drift) is never passed through.
            identities = json.loads((source / plan.IDENTITIES_TEMPLATE).read_text())
            identities['agent_gid'] = '@AGENT_GROUP_ID@'
            (templates / plan.IDENTITIES_TEMPLATE).write_text(json.dumps(identities))
            with self.assertRaisesRegex(plan.PlanError, '@AGENT_GROUP_ID@'):
                plan.build(values, templates)
        with self.assertRaisesRegex(plan.PlanError, '@X@'):
            plan.substitute('a @X@ b', {})

    def test_security_critical_plist_keys_cannot_be_dropped(self):
        values = plan.validate_inputs(dict(INPUTS))
        template = (plan.TEMPLATES / plan.PLIST_TEMPLATE).read_text()
        weakened = [
            template.replace('<key>AbandonProcessGroup</key><true/>', '<key>AbandonProcessGroup</key><false/>'),
            template.replace('<key>AbandonProcessGroup</key><true/>', ''),
            template.replace('<key>HardResourceLimits</key><dict><key>Core</key><integer>0</integer></dict>', ''),
            template.replace('<key>SoftResourceLimits</key><dict><key>Core</key><integer>0</integer></dict>', '<key>SoftResourceLimits</key><dict><key>Core</key><integer>1</integer></dict>'),
            template.replace('<key>StandardErrorPath</key><string>/dev/null</string>', '<key>StandardErrorPath</key><string>/tmp/log</string>'),
            template.replace('<key>StandardOutPath</key><string>/dev/null</string>', ''),
            template.replace('</dict></plist>', '<key>EnvironmentVariables</key><dict/></dict></plist>'),
            template.replace('versions/@VERSION@/vaultwarden-accessd', 'versions/current/vaultwarden-accessd'),
        ]
        self.assertTrue(all(w != template for w in weakened))
        for text in weakened:
            with self.subTest(text=text[-120:]), self.assertRaises(plan.PlanError):
                plan.resolve_plist(text, values)

    def test_output_directory_must_be_new_or_empty_and_writes_stay_inside_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            sandbox = Path(temporary) / 'sandbox'; sandbox.mkdir()
            (sandbox / 'sibling.txt').write_text('untouched\n')
            before = tree(sandbox)
            output = sandbox / 'plan'
            with patch.object(subprocess, 'run', side_effect=AssertionError('no process')), \
                    patch.object(subprocess, 'Popen', side_effect=AssertionError('no process')), \
                    patch.object(os, 'system', side_effect=AssertionError('no process')):
                code, _ = quiet(plan.main, argv(output))
            self.assertEqual(code, 0)
            after = tree(sandbox)
            self.assertEqual([entry for entry in after if not entry[0].startswith('plan')], before)
            self.assertEqual(sorted(p for p, _ in after if p.startswith('plan')), ['plan', 'plan/com.cantolla.vaultwarden-accessd.plist', 'plan/native-identities.json', 'plan/plan.json'])
            self.assertNotIn('subprocess', vars(plan))
            # Re-running into the populated directory refuses rather than overwriting.
            code, err = quiet(plan.main, argv(output))
            self.assertEqual(code, 2); self.assertIn('empty', err)
            self.assertEqual(tree(sandbox), after)
            # A symlinked output directory is refused and nothing is written through it.
            target = sandbox / 'target'; target.mkdir()
            link = sandbox / 'link'; link.symlink_to(target)
            code, _ = quiet(plan.main, argv(link))
            self.assertEqual(code, 2)
            self.assertEqual(list(target.iterdir()), [])
            # A missing parent is never created.
            code, _ = quiet(plan.main, argv(sandbox / 'missing' / 'plan'))
            self.assertEqual(code, 2)
            self.assertFalse((sandbox / 'missing').exists())

    def test_system_locations_are_refused(self):
        for location in ['/Library/VaultwardenAccess', '/Library/LaunchDaemons', '/Library', '/System/x', '/etc/plan']:
            with self.subTest(location=location), patch.object(Path, 'mkdir', side_effect=AssertionError('no mkdir')):
                with self.assertRaisesRegex(plan.PlanError, 'system location'):
                    plan.prepare_output(Path(location))

    def test_bundle_cross_check_binds_version_and_payload_hashes(self):
        with tempfile.TemporaryDirectory() as temporary:
            app = Path(temporary) / 'companion_slice.app'
            helpers = app / 'Contents/Helpers'; helpers.mkdir(parents=True)
            (app / 'Contents/Resources').mkdir()
            payloads = []
            for name in ['vaultwarden-accessd', 'vw-access']:
                (helpers / name).write_bytes(b'synthetic ' + name.encode())
                payloads.append({'path': f'Contents/Helpers/{name}', 'sha256': hashlib.sha256((helpers / name).read_bytes()).hexdigest(), 'executable': True})
            manifest = {'platform': 'macos', 'architecture': 'aarch64', 'cli_version': '0.5.4', 'roles': {'protected_provider': True}, 'payloads': payloads}
            def store(**changes):
                (app / 'Contents/Resources/bundle.json').write_text(json.dumps(dict(manifest, **changes)))
            store()
            output = Path(temporary) / 'plan'
            code, _ = quiet(plan.main, argv(output) + ['--bundle', str(app)])
            self.assertEqual(code, 0)
            files = {e['destination']: e for e in json.loads((output / 'plan.json').read_text())['files']}
            self.assertEqual(files['/Library/VaultwardenAccess/versions/0.5.4/vaultwarden-accessd']['sha256'], payloads[0]['sha256'])
            for changes in [{'cli_version': '0.5.5'}, {'architecture': 'x86_64'}, {'roles': {'protected_provider': False}}, {'payloads': payloads[1:]}]:
                store(**changes)
                with self.subTest(changes=changes), self.assertRaises(plan.PlanError):
                    plan.check_bundle(app, '0.5.4')
            store()
            (helpers / 'vaultwarden-accessd').write_bytes(b'replaced')
            with self.assertRaisesRegex(plan.PlanError, 'damaged'):
                plan.check_bundle(app, '0.5.4')

    def test_shipped_templates_resolve_with_their_declared_placeholders_only(self):
        values = plan.validate_inputs(dict(INPUTS))
        outputs = plan.build(values)
        self.assertLessEqual(len(outputs[plan.IDENTITIES_NAME]), plan.IDENTITIES_MAX)
        launchd = (plan.TEMPLATES / plan.PLIST_TEMPLATE).read_text()
        self.assertEqual(sorted(set(plan.PLACEHOLDER.findall(launchd))), ['@AGENT_GID@', '@PROVIDER_ACCOUNT@', '@PROVIDER_GROUP@', '@VERSION@'])


if __name__ == '__main__':
    unittest.main()
