#!/usr/bin/env python3
"""Native provider installer tests.

Everything runs under a temporary --root prefix with fake dscl, dseditgroup,
launchctl, chown, stat and codesign on a private tool directory. No test uses
sudo, creates an account, writes to /Library or talks to the real launchd.
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('installer', HERE / 'macos-provider-install.py')
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)
plan = installer.plan

OPERATOR_UUID = 'fedcba9876543210fedcba9876543210'
PROVIDER_UUID = '0123456789abcdef0123456789abcdef'
INPUTS = {
    'provider_account': '_vwaccess', 'provider_group': '_vwaccess', 'provider_uid': '491', 'provider_uuid': PROVIDER_UUID,
    'operator_uid': '501', 'operator_uuid': OPERATOR_UUID, 'human_gid': '492', 'agent_gid': '493',
}
LABEL = 'com.cantolla.vaultwarden-accessd'
ROOT = '/Library/VaultwardenAccess'

# One script implements every fake tool; state lives next to it.
FAKE = r'''
import json, os, plistlib, sys
from pathlib import Path
HERE = Path(__file__).resolve().parent
STATE = HERE / 'state.json'
name, args = sys.argv[1], sys.argv[2:]
state = json.loads(STATE.read_text())
with open(HERE / 'calls.log', 'a') as log:
    log.write(json.dumps([name] + args) + '\n')
def save():
    STATE.write_text(json.dumps(state, indent=1, sort_keys=True))
def fail(code, message):
    sys.stderr.write(message + '\n'); sys.exit(code)
def key(path):
    info = os.lstat(path)
    return f'{info.st_ino}:{info.st_birthtime if hasattr(info, "st_birthtime") else info.st_ctime_ns}'
users, groups = state['users'], state['groups']
if name == 'dscl':
    assert args[0] == '.'
    op, record = args[1], args[2]
    kind, _, rname = record.strip('/').partition('/')
    table = users if kind == 'Users' else groups
    if op == '-list':
        for n, attrs in sorted(table.items()):
            if args[3] in attrs:
                print(n, attrs[args[3]])
    elif op == '-read':
        if rname not in table:
            fail(56, 'eDSRecordNotFound')
        value = table[rname].get(args[3])
        if value is None:
            fail(181, 'No such key: ' + args[3])
        print(f'{args[3]}: {value}')
    elif op == '-create':
        if state.get('fail_create'):
            fail(1, 'create failed')
        table.setdefault(rname, {})
        if len(args) > 3:
            table[rname][args[3]] = ' '.join(args[4:])
        save()
    elif op == '-delete':
        table.pop(rname, None); save()
    else:
        fail(2, 'unsupported')
elif name == 'dseditgroup':
    opts = dict(zip(args[0:-1:2], args[1:-1:2])); group = args[-1]
    if opts['-o'] == 'create':
        if group in groups: fail(1, 'exists')
        groups[group] = {'PrimaryGroupID': opts['-i'], 'RealName': opts['-r']}
    elif opts['-o'] == 'edit':
        members = groups[group].get('GroupMembership', '').split()
        if '-a' in opts and opts['-a'] not in members: members.append(opts['-a'])
        if '-d' in opts and opts['-d'] in members: members.remove(opts['-d'])
        if members: groups[group]['GroupMembership'] = ' '.join(members)
        else: groups[group].pop('GroupMembership', None)
    elif opts['-o'] == 'delete':
        groups.pop(group, None)
    save()
elif name == 'launchctl':
    service = state['launchd']
    op = args[0]
    if op == 'print':
        if not service['loaded']: fail(113, 'Could not find service')
        print(json.dumps(service))
    elif op == 'print-disabled':
        print('disabled services = {')
        print('\t"com.cantolla.vaultwarden-accessd" => ' + ('disabled' if service['disabled'] else 'enabled'))
        print('}')
    elif op == 'disable': service['disabled'] = True; save()
    elif op == 'enable': service['disabled'] = False; save()
    elif op == 'bootout':
        if not service['loaded']: fail(3, 'No such process')
        service['loaded'] = False; save()
    elif op == 'bootstrap':
        if service['disabled']: fail(5, 'Bootstrap failed: 5: Input/output error')
        if state.get('fail_bootstrap'): fail(5, 'Bootstrap failed')
        program = plistlib.loads(Path(args[2]).read_bytes())['ProgramArguments'][0]
        service['loaded'] = True; service['program'] = program; save()
elif name == 'chown':
    assert args[0] == '-h'
    uid, gid = args[1].split(':')
    state['owners'][key(args[2])] = [int(uid), int(gid)]; save()
elif name == 'stat':
    assert args[:2] == ['-f', '%u:%g']
    if not os.path.lexists(args[2]): fail(1, 'No such file')
    owner = state['owners'].get(key(args[2]))
    if owner is None:
        info = os.lstat(args[2]); owner = [info.st_uid, info.st_gid]
    print(f'{owner[0]}:{owner[1]}')
elif name == 'codesign':
    assert args[:2] == ['--verify', '--strict']
    if b'UNSIGNED' in Path(args[2]).read_bytes(): fail(1, 'code object is not signed at all')
'''


class Host:
    """A temporary root, fake tool directory and synthetic bundles."""

    def __init__(self, base):
        self.base = Path(os.path.realpath(base))
        self.root = self.base / 'root'
        (self.root / 'Library/LaunchDaemons').mkdir(parents=True)
        self.tools = self.base / 'tools'
        self.tools.mkdir()
        (self.tools / 'fake.py').write_text(FAKE)
        for name in installer.SYSTEM_TOOLS:
            path = self.tools / name
            path.write_text(f'#!/bin/sh\nexec "{sys.executable}" -I -S "{self.tools / "fake.py"}" {name} "$@"\n')
            path.chmod(0o755)
        self.write_state({
            'users': {'root': {'UniqueID': '0', 'GeneratedUID': 'FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000000', 'PrimaryGroupID': '0'},
                      'sixto': {'UniqueID': '501', 'GeneratedUID': installer.generated_uid(OPERATOR_UUID), 'PrimaryGroupID': '20'}},
            'groups': {'wheel': {'PrimaryGroupID': '0'}, 'staff': {'PrimaryGroupID': '20'}},
            'launchd': {'loaded': False, 'disabled': False}, 'owners': {}})

    def state(self):
        return json.loads((self.tools / 'state.json').read_text())

    def write_state(self, state):
        (self.tools / 'state.json').write_text(json.dumps(state))

    def update(self, function):
        state = self.state(); function(state); self.write_state(state)

    def calls(self):
        log = self.tools / 'calls.log'
        return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []

    def mutating_calls(self):
        reads = {('dscl', '-list'), ('dscl', '-read'), ('launchctl', 'print'), ('launchctl', 'print-disabled'), ('stat', '-f'), ('codesign', '--verify')}
        return [c for c in self.calls() if (c[0], c[2] if c[0] == 'dscl' else c[1]) not in reads]

    def bundle(self, version, payload_extra=b'', tag=''):
        app = self.base / f'bundle-{version}{tag}' / 'companion_slice.app'
        helpers = app / 'Contents/Helpers'
        helpers.mkdir(parents=True)
        (app / 'Contents/Resources').mkdir()
        payloads = []
        for name in plan.BINARIES:
            (helpers / name).write_bytes(f'synthetic {name} {version}'.encode() + payload_extra)
            (helpers / name).chmod(0o755)
            payloads.append({'path': f'Contents/Helpers/{name}', 'executable': True,
                             'sha256': hashlib.sha256((helpers / name).read_bytes()).hexdigest()})
        (app / 'Contents/Resources/bundle.json').write_text(json.dumps({
            'platform': 'macos', 'architecture': 'aarch64', 'cli_version': version,
            'roles': {'protected_provider': True}, 'payloads': payloads}))
        return app

    def plan(self, version, bundle):
        output = self.base / f'plan-{version}'
        argv = ['--output', str(output), '--bundle', str(bundle), f'--version={version}']
        argv += [f'--{k.replace("_", "-")}={v}' for k, v in INPUTS.items()]
        with contextlib.redirect_stdout(io.StringIO()):
            self_code = plan.main(argv)
        assert self_code == 0
        return output

    def path(self, destination):
        return self.root / destination.lstrip('/')

    def provision_credentials(self):
        for name in plan.STATE_FILES:
            path = self.path(f'{ROOT}/state/{name}')
            path.write_bytes(b'synthetic credential placeholder\n')
            path.chmod(0o600)
            info = os.lstat(path)
            birth = info.st_birthtime if hasattr(info, 'st_birthtime') else info.st_ctime_ns
            self.update(lambda s, k=f'{info.st_ino}:{birth}': s['owners'].__setitem__(k, [491, 491]))

    def snapshot(self):
        files = []
        for path in sorted(self.root.rglob('*')):
            info = os.lstat(path)
            files.append((str(path.relative_to(self.root)), oct(info.st_mode), path.read_bytes() if path.is_file() else None))
        return files


class InstallerTestCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.host = Host(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        self.env = patch.dict(os.environ, {installer.FAKE_TOOLS_ENV: str(self.host.tools)})
        self.env.start(); self.addCleanup(self.env.stop)
        self.platform = patch.object(installer, 'host_platform', return_value=('darwin', 'arm64'))
        self.platform.start(); self.addCleanup(self.platform.stop)
        self.euid = patch.object(installer, 'effective_uid', return_value=0)
        self.euid.start(); self.addCleanup(self.euid.stop)
        self.bundle1 = self.host.bundle('0.5.4')
        self.plan1 = self.host.plan('0.5.4', self.bundle1)

    def run_installer(self, *argv):
        lines, err = [], io.StringIO()
        with contextlib.redirect_stderr(err):
            code = installer.main(list(argv) + ['--root', str(self.host.root)], out=lines.append)
        return code, '\n'.join(lines), err.getvalue()

    def install(self, *extra, plan_dir=None, bundle=None):
        return self.run_installer('install', '--plan', str(plan_dir or self.plan1), '--bundle', str(bundle or self.bundle1), *extra)

    def assertOk(self, result, code=0):
        self.assertEqual(result[0], code, result[1] + result[2])
        return result

    def receipt(self):
        return json.loads(self.host.path(f'{ROOT}/installer-receipt.json').read_text())


class DryRunTests(InstallerTestCase):
    def test_dry_run_prints_every_action_and_writes_nothing(self):
        before = self.host.snapshot()
        state = self.host.state()
        for argv in [['plan', '--plan', str(self.plan1), '--bundle', str(self.bundle1)],
                     ['install', '--dry-run', '--plan', str(self.plan1), '--bundle', str(self.bundle1)],
                     ['--plan', str(self.plan1), '--bundle', str(self.bundle1)]]:
            with self.subTest(argv=argv[0]):
                code, out, _ = self.assertOk(self.run_installer(*argv))
                for expected in ['would run: dseditgroup -o create -i 491', 'would run: dseditgroup -o create -i 492',
                                 'would run: dseditgroup -o create -i 493', 'would run: dscl . -create /Users/_vwaccess UniqueID 491',
                                 f'would: mkdir {ROOT}/state (_vwaccess:_vwaccess 0700)', f'would: mkdir {ROOT}/run/human (_vwaccess:_vwhuman 0750)',
                                 f'would: mkdir {ROOT}/run/agent (_vwaccess:_vwagent 0750)', f'would: mkdir {ROOT}/run/ssh (_vwaccess:_vwaccess 0700)',
                                 f'would: install version 0.5.4 into {ROOT}/versions/0.5.4', f'would: write {ROOT}/native-identities.json',
                                 f'would: write /Library/LaunchDaemons/{LABEL}.plist', f'would run: launchctl disable system/{LABEL}',
                                 'would run: dseditgroup -o edit -a sixto -t user _vwhuman', 'Next manual steps', 'nothing was changed']:
                    self.assertIn(expected, out)
                self.assertNotIn('launchctl bootstrap', out)
        self.assertEqual(self.host.snapshot(), before)
        self.assertEqual(self.host.mutating_calls(), [])
        self.assertEqual({k: v for k, v in self.host.state().items()}, state)

    def test_dry_run_needs_no_root_but_mutation_does(self):
        self.euid.stop(); self.addCleanup(self.euid.start)
        with patch.object(installer, 'effective_uid', return_value=501):
            self.assertOk(self.run_installer('plan', '--plan', str(self.plan1), '--bundle', str(self.bundle1)))
            for argv in [['install', '--plan', str(self.plan1), '--bundle', str(self.bundle1)], ['uninstall', '--acknowledge-active-work'],
                         ['rollback', '--confirm-state-compatible', '--acknowledge-active-work']]:
                code, _, err = self.run_installer(*argv)
                self.assertEqual(code, 2); self.assertIn('must run as root', err)
        self.assertEqual(self.host.mutating_calls(), [])
        self.assertFalse(self.host.path(ROOT).exists())

    def test_wrong_architecture_or_os_is_refused_for_every_command(self):
        for host in [('darwin', 'x86_64'), ('linux', 'aarch64'), ('darwin', 'arm64e'), ('win32', 'AMD64')]:
            with self.subTest(host=host), patch.object(installer, 'host_platform', return_value=host):
                for argv in [['plan', '--plan', str(self.plan1), '--bundle', str(self.bundle1)], ['status'],
                             ['install', '--plan', str(self.plan1), '--bundle', str(self.bundle1)]]:
                    code, _, err = self.run_installer(*argv)
                    self.assertEqual(code, 2); self.assertIn('Apple Silicon', err)
        self.assertEqual(self.host.calls(), [])

    def test_test_prefix_requires_fake_tools(self):
        with patch.dict(os.environ, {}, clear=False):
            del os.environ[installer.FAKE_TOOLS_ENV]
            code, _, err = self.run_installer('plan', '--plan', str(self.plan1), '--bundle', str(self.bundle1))
        self.assertEqual(code, 2); self.assertIn('fake tools', err)
        self.assertEqual(installer.SYSTEM_TOOLS['launchctl'], '/bin/launchctl')


class InstallTests(InstallerTestCase):
    def test_fresh_install_creates_accounts_layout_version_and_disabled_service(self):
        code, out, _ = self.assertOk(self.install())
        state = self.host.state()
        self.assertEqual(state['groups']['_vwaccess']['PrimaryGroupID'], '491')
        self.assertEqual(state['groups']['_vwhuman']['GroupMembership'].split(), ['_vwaccess', 'sixto'])
        self.assertEqual(state['groups']['_vwagent']['GroupMembership'].split(), ['_vwaccess'])
        user = state['users']['_vwaccess']
        self.assertEqual((user['UniqueID'], user['PrimaryGroupID'], user['UserShell'], user['NFSHomeDirectory'], user['IsHidden'], user['Password']),
                         ('491', '491', '/usr/bin/false', '/var/empty', '1', '*'))
        self.assertEqual(user['GeneratedUID'], '01234567-89AB-CDEF-0123-456789ABCDEF')
        document = json.loads((self.plan1 / 'plan.json').read_text())
        owners = installer.Installer(self.host.root, True, out=lambda _: None)
        for entry in document['directories']:
            self.assertEqual(owners.inspect(entry, 'dir'), [], entry['path'])
        for entry in document['files']:
            found = owners.inspect(entry, 'file')
            if entry['created_by'] == 'operator':
                self.assertIsNone(found, entry['path'])  # credentials are never created
            else:
                self.assertEqual(found, [], entry['path'])
        self.assertEqual(self.host.path(f'/Library/LaunchDaemons/{LABEL}.plist').read_bytes(), (self.plan1 / f'{LABEL}.plist').read_bytes())
        self.assertEqual(self.host.path(f'{ROOT}/versions/0.5.4/vaultwarden-accessd').read_bytes(),
                         (self.bundle1 / 'Contents/Helpers/vaultwarden-accessd').read_bytes())
        self.assertEqual(state['launchd'], {'loaded': False, 'disabled': True})
        self.assertIn('Next manual steps', out)
        self.assertIn(f'sudo install -o _vwaccess -g _vwaccess -m 0600 /path/to/backend.json {ROOT}/state/backend.json', out)
        receipt = self.receipt()
        self.assertEqual((receipt['created'], receipt['active_version'], receipt['status']),
                         ({'users': ['_vwaccess'], 'groups': ['_vwaccess', '_vwhuman', '_vwagent']}, '0.5.4', 'installed'))
        self.assertNotIn('version', receipt['inputs'])
        # Never any process control of consumers, never a credential tool.
        self.assertFalse([c for c in self.host.calls() if c[0] == 'launchctl' and c[1] in ('kill', 'stop', 'remove')])
        self.assertEqual(sorted(os.listdir(self.host.path(f'{ROOT}/state'))), [])

    def test_rerun_is_idempotent_and_starts_once_credentials_exist(self):
        self.assertOk(self.install())
        snapshot, calls = self.host.snapshot(), len(self.host.mutating_calls())
        code, out, _ = self.assertOk(self.install())
        self.assertIn('No changes', out)
        self.assertEqual(self.host.snapshot(), snapshot)
        self.assertEqual(len(self.host.mutating_calls()), calls)
        self.host.provision_credentials()
        self.assertOk(self.install())
        state = self.host.state()['launchd']
        self.assertEqual((state['loaded'], state['disabled'], state['program']), (True, False, f'{ROOT}/versions/0.5.4/vaultwarden-accessd'))
        self.assertEqual(self.host.mutating_calls()[-2:], [['launchctl', 'enable', f'system/{LABEL}'],
                                                           ['launchctl', 'bootstrap', 'system', str(self.host.path(f'/Library/LaunchDaemons/{LABEL}.plist'))]])
        code, out, _ = self.assertOk(self.install())
        self.assertIn('No changes', out)
        self.assertOk(self.run_installer('status'))

    def test_identifier_and_name_collisions_are_refused_before_any_write(self):
        cases = {
            'uid taken': lambda s: s['users'].__setitem__('other', {'UniqueID': '491', 'GeneratedUID': 'AA'}),
            'gid taken': lambda s: s['groups'].__setitem__('other', {'PrimaryGroupID': '492'}),
            'group name with other gid': lambda s: s['groups'].__setitem__('_vwagent', {'PrimaryGroupID': '700'}),
            'user name with other uid': lambda s: s['users'].__setitem__('_vwaccess', {'UniqueID': '700', 'GeneratedUID': installer.generated_uid(PROVIDER_UUID)}),
            'uuid taken': lambda s: s['users'].__setitem__('other', {'UniqueID': '800', 'GeneratedUID': installer.generated_uid(PROVIDER_UUID)}),
            'operator missing': lambda s: s['users'].pop('sixto'),
            'operator uuid differs': lambda s: s['users']['sixto'].__setitem__('GeneratedUID', installer.generated_uid('a' * 32)),
            'existing matching group not ours': lambda s: s['groups'].__setitem__('_vwhuman', {'PrimaryGroupID': '492'}),
            'existing matching user not ours': lambda s: s['users'].__setitem__('_vwaccess', {'UniqueID': '491', 'PrimaryGroupID': '491',
                                                                                               'GeneratedUID': installer.generated_uid(PROVIDER_UUID)}),
        }
        for label, change in cases.items():
            with self.subTest(label), tempfile.TemporaryDirectory() as temporary:
                host = Host(temporary)
                host.update(change)
                before = host.snapshot()
                with patch.dict(os.environ, {installer.FAKE_TOOLS_ENV: str(host.tools)}):
                    lines, err = [], io.StringIO()
                    with contextlib.redirect_stderr(err):
                        code = installer.main(['install', '--plan', str(self.plan1), '--bundle', str(self.bundle1), '--root', str(host.root)], out=lines.append)
                self.assertEqual(code, 2, lines)
                self.assertIn('macos-provider-install:', err.getvalue())
                self.assertEqual(host.mutating_calls(), [])
                self.assertEqual(host.snapshot(), before)

    def test_adopting_an_exactly_matching_existing_account_needs_the_explicit_flag(self):
        self.host.update(lambda s: s['groups'].__setitem__('_vwhuman', {'PrimaryGroupID': '492'}))
        code, _, err = self.install()
        self.assertEqual(code, 2); self.assertIn('--adopt-existing-accounts', err)
        self.assertOk(self.install('--adopt-existing-accounts'))
        receipt = self.receipt()
        self.assertEqual(receipt['adopted']['groups'], ['_vwhuman'])
        self.assertNotIn('_vwhuman', receipt['created']['groups'])
        self.assertIn('No changes', self.assertOk(self.install())[1])

    def test_preexisting_foreign_directory_is_refused_not_changed(self):
        target = self.host.path(f'{ROOT}/versions/0.5.4')
        target.mkdir(parents=True)
        (target / 'vaultwarden-accessd').write_bytes(b'someone else')
        code, _, err = self.install()
        self.assertEqual(code, 2); self.assertIn('refusing to change it', err)
        self.assertEqual((target / 'vaultwarden-accessd').read_bytes(), b'someone else')
        self.assertEqual(self.host.mutating_calls(), [])

    def test_hard_linked_bundle_payload_is_refused(self):
        os.link(self.bundle1 / 'Contents/Helpers/vw-access', self.host.base / 'second-link')
        code, _, err = self.install()
        self.assertEqual(code, 2); self.assertIn('hard links', err)
        self.assertEqual(self.host.mutating_calls(), [])
        self.assertFalse(self.host.path(ROOT).exists())

    def test_tampered_bundle_binary_is_refused(self):
        (self.bundle1 / 'Contents/Helpers/vaultwarden-accessd').write_bytes(b'tampered')
        code, _, err = self.install()
        self.assertEqual(code, 2); self.assertIn('damaged', err)
        self.assertEqual(self.host.mutating_calls(), [])
        # A bundle that is self-consistent but differs from the reviewed plan is refused too.
        rebuilt = self.host.bundle('0.5.4', payload_extra=b' rebuilt', tag='-rebuilt')
        code, _, err = self.install(bundle=rebuilt)
        self.assertEqual(code, 2); self.assertIn('differ from the reviewed plan', err)
        other_version = self.host.bundle('0.5.5')
        code, _, err = self.install(bundle=other_version)
        self.assertEqual(code, 2); self.assertIn('bundle invalid', err)
        self.assertEqual(self.host.mutating_calls(), [])

    def test_edited_plan_is_refused(self):
        plist = self.plan1 / f'{LABEL}.plist'
        plist.write_text(plist.read_text().replace('<key>AbandonProcessGroup</key><true/>', '<key>AbandonProcessGroup</key><false/>'))
        code, _, err = self.install()
        self.assertEqual(code, 2); self.assertIn('differs from a fresh resolution', err)
        self.assertEqual(self.host.mutating_calls(), [])

    def test_unsigned_binary_fails_verification_before_activation(self):
        app = self.host.bundle('0.6.0', payload_extra=b' UNSIGNED')
        code, _, err = self.install(plan_dir=self.host.plan('0.6.0', app), bundle=app)
        self.assertEqual(code, 2); self.assertIn('codesign', err)
        self.assertFalse(self.host.path(f'{ROOT}/versions/0.6.0').exists())
        self.assertFalse(self.host.path(f'/Library/LaunchDaemons/{LABEL}.plist').exists())
        # A partial staging directory is left for inspection; a re-run replaces only that.
        self.assertTrue(self.host.path(f'{ROOT}/versions/.staging-0.6.0').exists())
        code, out, err = self.install(plan_dir=self.host.base / 'plan-0.6.0', bundle=app)
        self.assertEqual(code, 2); self.assertIn('remove leftover staging directory', out)
        self.assertFalse(self.host.path(f'{ROOT}/versions/0.6.0').exists())


class LifecycleTests(InstallerTestCase):
    def setUp(self):
        super().setUp()
        self.assertOk(self.install())
        self.host.provision_credentials()
        self.assertOk(self.install())
        self.bundle2 = self.host.bundle('0.6.0')
        self.plan2 = self.host.plan('0.6.0', self.bundle2)

    def upgrade(self, *extra):
        return self.run_installer('upgrade', '--plan', str(self.plan2), '--bundle', str(self.bundle2), *extra)

    def test_upgrade_verifies_then_closes_admission_then_switches_in_order(self):
        start = len(self.host.calls())
        self.assertOk(self.upgrade('--acknowledge-active-work'))
        calls = self.host.calls()[start:]
        order = [c for c in calls if c[0] in ('launchctl', 'codesign') and c[1] not in ('print', 'print-disabled')]
        version = str(self.host.path(f'{ROOT}/versions/0.6.0'))
        staging = str(self.host.path(f'{ROOT}/versions/.staging-0.6.0'))
        self.assertEqual([c[0] for c in order[:4]], ['codesign'] * 4)
        self.assertTrue(order[0][3].startswith(staging) and order[2][3].startswith(version))
        self.assertEqual(order[4:], [['launchctl', 'disable', f'system/{LABEL}'], ['launchctl', 'bootout', f'system/{LABEL}'],
                                     ['launchctl', 'enable', f'system/{LABEL}'],
                                     ['launchctl', 'bootstrap', 'system', str(self.host.path(f'/Library/LaunchDaemons/{LABEL}.plist'))]])
        state = self.host.state()['launchd']
        self.assertEqual((state['loaded'], state['program']), (True, f'{ROOT}/versions/0.6.0/vaultwarden-accessd'))
        receipt = self.receipt()
        self.assertEqual((receipt['active_version'], receipt['previous_version'], sorted(receipt['versions'])), ('0.6.0', '0.5.4', ['0.5.4', '0.6.0']))
        self.assertTrue(self.host.path(f'{ROOT}/versions/0.5.4/vaultwarden-accessd').exists())
        self.assertEqual(self.host.path(f'/Library/LaunchDaemons/{LABEL}.plist').read_bytes(), (self.plan2 / f'{LABEL}.plist').read_bytes())
        self.assertOk(self.run_installer('status'))

    def test_upgrade_requires_acknowledgement_and_refuses_bad_input_without_touching_the_service(self):
        snapshot = self.host.snapshot()
        code, _, err = self.upgrade()
        self.assertEqual(code, 2); self.assertIn('--acknowledge-active-work', err)
        (self.bundle2 / 'Contents/Helpers/vw-access').write_bytes(b'tampered')
        code, _, err = self.upgrade('--acknowledge-active-work')
        self.assertEqual(code, 2)
        self.assertEqual(self.host.snapshot(), snapshot)
        self.assertEqual(self.host.state()['launchd']['loaded'], True)
        self.assertEqual(self.receipt()['active_version'], '0.5.4')

    def test_upgrade_dry_run_lists_the_order_and_changes_nothing(self):
        snapshot, calls = self.host.snapshot(), len(self.host.mutating_calls())
        code, out, _ = self.assertOk(self.upgrade('--dry-run'))
        lines = [line for line in out.splitlines() if line.startswith('would')]
        self.assertIn('install version 0.6.0', lines[0])
        self.assertEqual([line for line in lines if 'launchctl' in line],
                         [f'would run: launchctl disable system/{LABEL}', f'would run: launchctl bootout system/{LABEL}',
                          f'would run: launchctl enable system/{LABEL}', f'would run: launchctl bootstrap system {self.host.path(f"/Library/LaunchDaemons/{LABEL}.plist")}'])
        self.assertEqual(self.host.snapshot(), snapshot)
        self.assertEqual(len(self.host.mutating_calls()), calls)

    def test_rollback_switches_back_with_the_same_order(self):
        self.assertOk(self.upgrade('--acknowledge-active-work'))
        code, _, err = self.run_installer('rollback', '--acknowledge-active-work')
        self.assertEqual(code, 2); self.assertIn('--confirm-state-compatible', err)
        start = len(self.host.calls())
        self.assertOk(self.run_installer('rollback', '--acknowledge-active-work', '--confirm-state-compatible'))
        launchd = [c[1] for c in self.host.calls()[start:] if c[0] == 'launchctl' and c[1] not in ('print', 'print-disabled')]
        self.assertEqual(launchd, ['disable', 'bootout', 'enable', 'bootstrap'])
        state = self.host.state()['launchd']
        self.assertEqual(state['program'], f'{ROOT}/versions/0.5.4/vaultwarden-accessd')
        receipt = self.receipt()
        self.assertEqual((receipt['active_version'], receipt['previous_version']), ('0.5.4', '0.6.0'))
        self.assertTrue(self.host.path(f'{ROOT}/versions/0.6.0').exists())
        self.assertOk(self.run_installer('status'))

    def test_failed_bootstrap_after_switch_reports_and_rollback_recovers(self):
        self.host.update(lambda s: s.__setitem__('fail_bootstrap', True))
        code, _, err = self.upgrade('--acknowledge-active-work')
        self.assertEqual(code, 2); self.assertIn('use rollback', err)
        self.assertEqual(self.host.state()['launchd']['loaded'], False)
        self.host.update(lambda s: s.pop('fail_bootstrap'))
        self.assertOk(self.run_installer('rollback', '--acknowledge-active-work', '--confirm-state-compatible'))
        self.assertEqual(self.host.state()['launchd']['program'], f'{ROOT}/versions/0.5.4/vaultwarden-accessd')
        self.assertFalse(list(self.host.path('/Library/LaunchDaemons').glob('.*')))

    def test_rollback_refuses_a_changed_or_unknown_version(self):
        self.assertOk(self.upgrade('--acknowledge-active-work'))
        code, _, err = self.run_installer('rollback', '--to-version', '0.4.0', '--acknowledge-active-work', '--confirm-state-compatible')
        self.assertEqual(code, 2); self.assertIn('not installed by this installer', err)
        binary = self.host.path(f'{ROOT}/versions/0.5.4/vw-access')
        binary.parent.chmod(0o755); binary.chmod(0o755)
        binary.write_bytes(b'replaced'); binary.chmod(0o555); binary.parent.chmod(0o555)
        code, _, err = self.run_installer('rollback', '--acknowledge-active-work', '--confirm-state-compatible')
        self.assertEqual(code, 2); self.assertIn('failed verification', err)
        self.assertEqual(self.host.state()['launchd']['program'], f'{ROOT}/versions/0.6.0/vaultwarden-accessd')
        self.assertEqual(self.receipt()['active_version'], '0.6.0')

    def test_existing_different_version_directory_is_never_overwritten(self):
        foreign = self.host.path(f'{ROOT}/versions/0.6.0')
        foreign.mkdir()
        (foreign / 'vaultwarden-accessd').write_bytes(b'someone else')
        code, _, err = self.upgrade('--acknowledge-active-work')
        self.assertEqual(code, 2); self.assertIn('never overwritten', err)
        self.assertEqual((foreign / 'vaultwarden-accessd').read_bytes(), b'someone else')
        self.assertEqual(self.receipt()['active_version'], '0.5.4')
        self.assertEqual(self.host.state()['launchd']['program'], f'{ROOT}/versions/0.5.4/vaultwarden-accessd')
        # A changed active version is not silently repaired by a re-run either.
        binary = self.host.path(f'{ROOT}/versions/0.5.4/vw-access')
        binary.parent.chmod(0o755); binary.chmod(0o755)
        binary.write_bytes(b'replaced'); binary.chmod(0o555); binary.parent.chmod(0o555)
        code, _, err = self.install()
        self.assertEqual(code, 2); self.assertIn('never overwritten', err)
        self.assertEqual(binary.read_bytes(), b'replaced')

    def test_installed_binary_with_second_hard_link_fails_status(self):
        os.link(self.host.path(f'{ROOT}/versions/0.5.4/vw-access'), self.host.base / 'escape')
        code, out, _ = self.run_installer('status')
        self.assertEqual(code, 1); self.assertIn('2 hard links', out)

    def test_uninstall_preserves_state_accounts_and_keychain(self):
        code, _, err = self.run_installer('uninstall')
        self.assertEqual(code, 2); self.assertIn('--acknowledge-active-work', err)
        code, out, _ = self.assertOk(self.run_installer('uninstall', '--acknowledge-active-work'))
        self.assertFalse(self.host.path(f'/Library/LaunchDaemons/{LABEL}.plist').exists())
        self.assertFalse(self.host.path(f'{ROOT}/versions').exists())
        self.assertFalse(self.host.path(f'{ROOT}/native-identities.json').exists())
        self.assertFalse(self.host.path(f'{ROOT}/run').exists())
        self.assertEqual(sorted(os.listdir(self.host.path(f'{ROOT}/state'))), sorted(plan.STATE_FILES))
        state = self.host.state()
        self.assertEqual(state['launchd']['loaded'], False)
        self.assertIn('_vwaccess', state['users']); self.assertIn('_vwhuman', state['groups'])
        self.assertIn('never deleted by the installer', out)
        self.assertEqual(self.receipt()['status'], 'uninstalled')
        # A later install recognizes its own accounts and the preserved state.
        self.assertOk(self.install())
        self.assertEqual(self.host.state()['launchd']['loaded'], True)

    def test_uninstall_retains_changed_resources_and_reports_incomplete(self):
        socket_dir = self.host.path(f'{ROOT}/run/agent')
        (socket_dir / 'agent.sock').write_text('')
        code, out, _ = self.run_installer('uninstall', '--acknowledge-active-work')
        self.assertEqual(code, 3)
        self.assertIn('retained: /Library/VaultwardenAccess/run/agent (not empty', out)
        self.assertTrue((socket_dir / 'agent.sock').exists())

    def test_purge_removes_state_and_owned_accounts_only_when_asked(self):
        code, _, err = self.run_installer('uninstall', '--acknowledge-active-work', '--remove-accounts')
        self.assertEqual(code, 2); self.assertIn('requires --purge', err)
        self.assertOk(self.run_installer('uninstall', '--acknowledge-active-work', '--purge'))
        self.assertFalse(self.host.path(f'{ROOT}/state').exists())
        self.assertIn('_vwaccess', self.host.state()['users'])
        self.assertOk(self.run_installer('uninstall', '--acknowledge-active-work', '--purge', '--remove-accounts'))
        state = self.host.state()
        self.assertNotIn('_vwaccess', state['users'])
        for group in ['_vwaccess', '_vwhuman', '_vwagent']:
            self.assertNotIn(group, state['groups'])
        self.assertIn('sixto', state['users'])  # the operator account is never touched
        self.assertFalse(self.host.path(ROOT).exists())
        self.assertFalse([c for c in self.host.calls() if c[0] == 'security'])

    def test_foreign_launch_daemon_plist_is_retained(self):
        plist = self.host.path(f'/Library/LaunchDaemons/{LABEL}.plist')
        plist.write_bytes(plist.read_bytes().replace(b'127.0.0.1:8443', b'0.0.0.0:8443'))
        code, _, err = self.upgrade('--acknowledge-active-work')
        self.assertEqual(code, 2); self.assertIn('not written by this installer', err)
        code, out, _ = self.run_installer('uninstall', '--acknowledge-active-work')
        self.assertEqual(code, 3); self.assertIn('not written by this installer', out)
        self.assertTrue(plist.exists())


if __name__ == '__main__':
    unittest.main()
