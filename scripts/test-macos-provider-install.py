#!/usr/bin/env python3
"""Native provider installer tests.

Everything runs under a temporary --root prefix with fake dscl, dseditgroup,
dsmemberutil, launchctl, chown, stat, codesign and lipo on a private tool
directory. No test uses sudo, creates an account, writes to /Library or talks
to the real launchd. The fakes run in-process for speed (one test runs them as
real processes through their shell wrappers).
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
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
AGENT_UUID = 'aaaaaaaabbbbccccddddeeeeeeeeeeee'
INPUTS = {
    'provider_account': '_vwaccess', 'provider_group': '_vwaccess', 'provider_uid': '491', 'provider_uuid': PROVIDER_UUID,
    'operator_uid': '501', 'operator_uuid': OPERATOR_UUID, 'human_gid': '600', 'agent_gid': '601',
}
LABEL = 'com.cantolla.vaultwarden-accessd'
ROOT = '/Library/VaultwardenAccess'
TOOL_NAMES = ('dscl', 'dseditgroup', 'dsmemberutil', 'launchctl', 'chown', 'stat', 'codesign', 'lipo')
# The new command-line contract (review round 1); absent in the pre-review installer.
NEW_CONTRACT = hasattr(installer, 'signature_policy')

# One script implements every fake tool; state lives next to it. Output formats follow
# the real macOS tools (dscl bare record names, launchctl print fields, dsmemberutil text).
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
def is_member(user, group):
    return user in groups[group].get('GroupMembership', '').split() or users[user].get('PrimaryGroupID') == groups[group].get('PrimaryGroupID')
if name == 'dscl':
    assert args[0] == '.'
    op, record = args[1], args[2]
    kind, _, rname = record.strip('/').partition('/')
    table = users if kind == 'Users' else groups
    if op == '-list':
        for n, attrs in sorted(table.items()):
            # Real dscl prints a record that lacks the attribute as its bare name.
            print(f'{n} {attrs[args[3]]}' if args[3] in attrs else n)
    elif op == '-read':
        if rname not in table:
            fail(56, f'<dscl_cmd> DS Error: -14136 (eDSRecordNotFound)')
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
        if rname not in table:
            fail(56, f'<dscl_cmd> DS Error: -14136 (eDSRecordNotFound)')
        table.pop(rname); save()
    else:
        fail(2, 'unsupported')
elif name == 'dseditgroup':
    opts = dict(zip(args[0:-1:2], args[1:-1:2])); group = args[-1]
    if opts['-o'] == 'create':
        if group in groups: fail(1, 'exists')
        groups[group] = {'PrimaryGroupID': opts['-i'], 'RealName': opts['-r']}
    elif opts['-o'] == 'edit':
        if group not in groups: fail(64, 'Group not found.')
        members = groups[group].get('GroupMembership', '').split()
        if '-a' in opts and opts['-a'] not in members: members.append(opts['-a'])
        if '-d' in opts:
            if opts['-d'] not in members: fail(64, 'Record was not found.')
            members.remove(opts['-d'])
        if members: groups[group]['GroupMembership'] = ' '.join(members)
        else: groups[group].pop('GroupMembership', None)
    elif opts['-o'] == 'delete':
        if group not in groups: fail(64, 'Group not found.')
        groups.pop(group)
    save()
elif name == 'dsmemberutil':
    assert args[0] == 'checkmembership'
    opts = dict(zip(args[1::2], args[2::2]))
    if opts['-U'] not in users or opts['-G'] not in groups: fail(70, 'Unable to find user or group')
    print('user is a member of the group' if is_member(opts['-U'], opts['-G']) else 'user is not a member of the group')
elif name == 'launchctl':
    service = state['launchd']
    op = args[0]
    if op == 'print':
        if not service['loaded']: fail(113, f'Could not find service "{args[1].split("/", 1)[1]}" in domain for system')
        print(f'{args[1]} = {{')
        print('\tactive count = ' + ('1' if service['running'] else '0'))
        print('\tpath = /Library/LaunchDaemons/com.cantolla.vaultwarden-accessd.plist')
        print('\ttype = LaunchDaemon')
        print('\tstate = ' + ('running' if service['running'] else 'not running'))
        print(f'\tprogram = {service["program"]}')
        print('\tendpoints = {')
        print('\t\tstate = active')
        print('\t}')
        if service['running']: print('\tpid = 4242')
        print('\tlast exit code = ' + (str(service['last_exit']) if service.get('last_exit') is not None else '(never exited)'))
        print('}')
    elif op == 'print-disabled':
        print('disabled services = {')
        print('\t"com.apple.example" => enabled')
        if 'disabled' in service:
            print('\t"com.cantolla.vaultwarden-accessd" => ' + ('disabled' if service['disabled'] else 'enabled'))
        print('}')
    elif op == 'disable': service['disabled'] = True; save()
    elif op == 'enable': service['disabled'] = False; save()
    elif op == 'bootout':
        if not service['loaded']: fail(3, 'No such process')
        service.update(loaded=False, running=False); save()
    elif op == 'bootstrap':
        if service.get('disabled'): fail(5, 'Bootstrap failed: 5: Input/output error')
        if state.get('fail_bootstrap'): fail(5, 'Bootstrap failed')
        program = plistlib.loads(Path(args[2]).read_bytes())['ProgramArguments'][0]
        crash = state.get('crash_on_start')
        service.update(loaded=True, running=not crash, program=program, last_exit=78 if crash else None); save()
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
    data = Path(args[-1]).read_bytes()
    team = data.split(b'TEAM=')[1][:10].decode() if b'TEAM=' in data else None
    if args[0] == '-d':
        if b'UNSIGNED' in data: fail(1, f'{args[-1]}: code object is not signed at all')
        sys.stderr.write(f'Executable={args[-1]}\nIdentifier=example\n')
        if team: sys.stderr.write(f'Authority=Developer ID Application: Example ({team})\nTeamIdentifier={team}\n')
        else: sys.stderr.write('Signature=adhoc\nTeamIdentifier=not set\n')
    else:
        assert args[:2] == ['--verify', '--strict'], args
        if b'UNSIGNED' in data: fail(1, 'code object is not signed at all')
        if '-R' in args:
            requirement = args[args.index('-R') + 1]
            assert requirement.startswith('=anchor apple generic and certificate leaf[subject.OU] = "'), requirement
            if team != requirement.split('"')[1]: fail(3, 'test-requirement: code failed to satisfy specified code requirement(s)')
elif name == 'lipo':
    assert args[0] == '-archs'
    data = Path(args[1]).read_bytes()
    print('x86_64' if b'X86' in data else 'x86_64 arm64' if b'UNIVERSAL' in data else 'arm64')
'''
FAKE_CODE = compile(FAKE, 'fake.py', 'exec')
REAL_RUN = subprocess.run


def run_fake_in_process(command, **kwargs):
    """subprocess.run for the fake tool directory: the same script, executed in this process."""
    path = Path(command[0])
    if not (path.parent / 'fake.py').exists() or path.name not in TOOL_NAMES:
        return REAL_RUN(command, **kwargs)
    out, err, code = io.StringIO(), io.StringIO(), 0
    saved = sys.argv
    sys.argv = ['fake.py', path.name, *command[1:]]
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            exec(FAKE_CODE, {'__file__': str(path.parent / 'fake.py'), '__name__': '__fake__'})
    except SystemExit as stop:
        code = stop.code if isinstance(stop.code, int) else (0 if stop.code is None else 1)
    finally:
        sys.argv = saved
    return subprocess.CompletedProcess(command, code, out.getvalue(), err.getvalue())


def digest(plan_dir):
    return hashlib.sha256((Path(plan_dir) / 'plan.json').read_bytes()).hexdigest()


class Crash(BaseException):
    """Simulated power loss right after one completed mutation."""


class Host:
    """A temporary root, fake tool directory and synthetic bundles."""

    def __init__(self, base):
        self.base = Path(os.path.realpath(base))
        self.root = self.base / 'root'
        (self.root / 'Library/LaunchDaemons').mkdir(parents=True)
        self.tools = self.base / 'tools'
        self.tools.mkdir()
        (self.tools / 'fake.py').write_text(FAKE)
        for name in TOOL_NAMES:
            path = self.tools / name
            path.write_text(f'#!/bin/sh\nexec "{sys.executable}" -I -S "{self.tools / "fake.py"}" {name} "$@"\n')
            path.chmod(0o755)
        self.write_state({
            'users': {'root': {'UniqueID': '0', 'GeneratedUID': 'FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000000', 'PrimaryGroupID': '0'},
                      'sixto': {'UniqueID': '501', 'GeneratedUID': installer.generated_uid(OPERATOR_UUID), 'PrimaryGroupID': '20'}},
            'groups': {'wheel': {'PrimaryGroupID': '0', 'GroupMembership': 'root'}, 'staff': {'PrimaryGroupID': '20'},
                       'admin': {'PrimaryGroupID': '80', 'GroupMembership': 'root sixto'}},
            'launchd': {'loaded': False, 'running': False}, 'owners': {}})

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
        reads = {('dscl', '-list'), ('dscl', '-read'), ('launchctl', 'print'), ('launchctl', 'print-disabled'), ('stat', '-f'),
                 ('codesign', '--verify'), ('codesign', '-d'), ('lipo', '-archs'), ('dsmemberutil', 'checkmembership')}
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

    def plan(self, version, bundle, tag='', **overrides):
        output = self.base / f'plan-{version}{tag}'
        argv = ['--output', str(output), '--bundle', str(bundle), f'--version={version}']
        argv += [f'--{k.replace("_", "-")}={v}' for k, v in dict(INPUTS, **overrides).items()]
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

    def accounts(self):
        state = self.state()
        return state['users'], state['groups'], {k: v for k, v in state['launchd'].items()}


class InstallerTestCase(unittest.TestCase):
    IN_PROCESS = True

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.env = patch.dict(os.environ, {})
        self.env.start(); self.addCleanup(self.env.stop)
        for target, value in [('host_platform', ('darwin', 'arm64')), ('effective_uid', 0)]:
            patcher = patch.object(installer, target, return_value=value)
            setattr(self, target, patcher); patcher.start(); self.addCleanup(patcher.stop)
        self.euid = self.effective_uid
        if hasattr(installer, 'code_paths'):
            patcher = patch.object(installer, 'code_paths', return_value=[])
            patcher.start(); self.addCleanup(patcher.stop)
        if hasattr(installer, 'START_WAIT_SECONDS'):
            patcher = patch.multiple(installer, START_WAIT_SECONDS=0.0, START_POLL_SECONDS=0.0)
            patcher.start(); self.addCleanup(patcher.stop)
        if self.IN_PROCESS:
            patcher = patch.object(installer.subprocess, 'run', run_fake_in_process)
            patcher.start(); self.addCleanup(patcher.stop)
        self.use_host(self.temporary.name)

    def use_host(self, base):
        self.host = Host(base)
        os.environ[installer.FAKE_TOOLS_ENV] = str(self.host.tools)
        self.bundle1 = self.host.bundle('0.5.4')
        self.plan1 = self.host.plan('0.5.4', self.bundle1)

    def fresh_host(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.use_host(temporary.name)

    def run_installer(self, *argv):
        lines, err = [], io.StringIO()
        with contextlib.redirect_stderr(err):
            code = installer.main(list(argv) + ['--root', str(self.host.root)], out=lines.append)
        return code, '\n'.join(lines), err.getvalue()

    @staticmethod
    def pinned(plan_dir):
        return ['--expect-plan-sha256', digest(plan_dir), '--allow-development-signature'] if NEW_CONTRACT else []

    def install(self, *extra, plan_dir=None, bundle=None, pin=True):
        plan_dir = plan_dir or self.plan1
        return self.run_installer('install', '--plan', str(plan_dir), '--bundle', str(bundle or self.bundle1),
                                  *(self.pinned(plan_dir) if pin else []), *extra)

    def assertOk(self, result, code=0):
        self.assertEqual(result[0], code, result[1] + result[2])
        return result

    def receipt(self):
        return json.loads(self.host.path(f'{ROOT}/installer-receipt.json').read_text())

    def crash_after(self, step):
        """Raise Crash right after the step-th completed mutation (a tool call or an action)."""
        count = [0]
        act, tool = installer.Installer.act, installer.Installer.tool

        def tick(instance):
            if not instance.dry_run:
                count[0] += 1
                if count[0] == step:
                    raise Crash(step)

        def crashing_act(instance, description, function=None):
            result = act(instance, description, function)
            tick(instance)
            return result

        def crashing_tool(instance, name, *args, mutating, check=True):
            result = tool(instance, name, *args, mutating=mutating, check=check)
            if mutating:
                tick(instance)
            return result
        return patch.multiple(installer.Installer, act=crashing_act, tool=crashing_tool), count


class DryRunTests(InstallerTestCase):
    def test_dry_run_prints_every_action_and_writes_nothing(self):
        before = self.host.snapshot()
        state = self.host.state()
        for argv in [['plan', '--plan', str(self.plan1), '--bundle', str(self.bundle1)],
                     ['install', '--dry-run', '--plan', str(self.plan1), '--bundle', str(self.bundle1)],
                     ['--plan', str(self.plan1), '--bundle', str(self.bundle1)]]:
            with self.subTest(argv=argv[0]):
                code, out, _ = self.assertOk(self.run_installer(*argv))
                for expected in ['would run: dseditgroup -o create -i 491', 'would run: dseditgroup -o create -i 600',
                                 'would run: dseditgroup -o create -i 601', 'would run: dscl . -create /Users/_vwaccess UniqueID 491',
                                 f'would: mkdir {ROOT}/state (_vwaccess:_vwaccess 0700)', f'would: mkdir {ROOT}/run/human (_vwaccess:_vwhuman 0750)',
                                 f'would: mkdir {ROOT}/run/agent (_vwaccess:_vwagent 0750)', f'would: mkdir {ROOT}/run/ssh (_vwaccess:_vwaccess 0700)',
                                 f'would: install version 0.5.4 into {ROOT}/versions/0.5.4', f'would: write {ROOT}/native-identities.json',
                                 f'would: write /Library/LaunchDaemons/{LABEL}.plist', f'would run: launchctl disable system/{LABEL}',
                                 'would run: dseditgroup -o edit -a sixto -t user _vwhuman', 'Next manual steps', 'nothing was changed',
                                 f'plan.json sha256: {digest(self.plan1)}', f'pass --expect-plan-sha256 {digest(self.plan1)}']:
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
            if entry['created_by'] == 'operator' or 'written_when' in entry:
                self.assertIsNone(found, entry['path'])  # credentials are never created
            else:
                self.assertEqual(found, [], entry['path'])
        self.assertEqual(self.host.path(f'/Library/LaunchDaemons/{LABEL}.plist').read_bytes(), (self.plan1 / f'{LABEL}.plist').read_bytes())
        self.assertEqual(self.host.path(f'{ROOT}/versions/0.5.4/vaultwarden-accessd').read_bytes(),
                         (self.bundle1 / 'Contents/Helpers/vaultwarden-accessd').read_bytes())
        self.assertEqual(state['launchd'], {'loaded': False, 'running': False, 'disabled': True})
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
            'gid taken': lambda s: s['groups'].__setitem__('other', {'PrimaryGroupID': '600'}),
            'group name with other gid': lambda s: s['groups'].__setitem__('_vwagent', {'PrimaryGroupID': '700'}),
            'user name with other uid': lambda s: s['users'].__setitem__('_vwaccess', {'UniqueID': '700', 'GeneratedUID': installer.generated_uid(PROVIDER_UUID)}),
            'uuid taken': lambda s: s['users'].__setitem__('other', {'UniqueID': '800', 'GeneratedUID': installer.generated_uid(PROVIDER_UUID)}),
            'operator missing': lambda s: s['users'].pop('sixto'),
            'operator uuid differs': lambda s: s['users']['sixto'].__setitem__('GeneratedUID', installer.generated_uid('a' * 32)),
            'existing matching group not ours': lambda s: s['groups'].__setitem__('_vwhuman', {'PrimaryGroupID': '600'}),
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
                        code = installer.main(['install', '--plan', str(self.plan1), '--bundle', str(self.bundle1), *self.pinned(self.plan1),
                                               '--root', str(host.root)], out=lines.append)
                self.assertEqual(code, 2, lines)
                self.assertIn('macos-provider-install:', err.getvalue())
                self.assertEqual(host.mutating_calls(), [])
                self.assertEqual(host.snapshot(), before)

    def test_adopting_an_exactly_matching_existing_account_needs_the_explicit_flag(self):
        self.host.update(lambda s: s['groups'].__setitem__('_vwhuman', {'PrimaryGroupID': '600'}))
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
        return self.run_installer('upgrade', '--plan', str(self.plan2), '--bundle', str(self.bundle2), *self.pinned(self.plan2), *extra)

    def test_upgrade_verifies_then_closes_admission_then_switches_in_order(self):
        start = len(self.host.calls())
        self.assertOk(self.upgrade('--acknowledge-active-work'))
        calls = self.host.calls()[start:]
        order = [c for c in calls if c[0] in ('launchctl', 'codesign') and c[1] not in ('print', 'print-disabled', '-d')]
        version = str(self.host.path(f'{ROOT}/versions/0.6.0'))
        staging = str(self.host.path(f'{ROOT}/versions/.staging-0.6.0'))
        self.assertEqual([c[0] for c in order[:4]], ['codesign'] * 4)
        self.assertTrue(order[0][-1].startswith(staging) and order[2][-1].startswith(version))
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
        self.assertOk(self.run_installer('uninstall', '--acknowledge-active-work', '--purge', '--remove-accounts', '--confirm-secrets-removed'))
        state = self.host.state()
        self.assertNotIn('_vwaccess', state['users'])
        for group in ['_vwaccess', '_vwhuman', '_vwagent']:
            self.assertNotIn(group, state['groups'])
        self.assertIn('sixto', state['users'])  # the operator account is never touched
        self.assertEqual(state['groups']['admin']['GroupMembership'], 'root sixto')
        # Only the root-owned tombstones remain, so a recreated account can never reuse the GeneratedUID.
        self.assertEqual(os.listdir(self.host.path(ROOT)), ['account-tombstones.json'])
        self.assertFalse([c for c in self.host.calls() if c[0] == 'security'])

    def test_foreign_launch_daemon_plist_is_retained(self):
        plist = self.host.path(f'/Library/LaunchDaemons/{LABEL}.plist')
        plist.write_bytes(plist.read_bytes().replace(b'127.0.0.1:8443', b'0.0.0.0:8443'))
        code, _, err = self.upgrade('--acknowledge-active-work')
        self.assertEqual(code, 2); self.assertIn('not written by this installer', err)
        code, out, _ = self.run_installer('uninstall', '--acknowledge-active-work')
        self.assertEqual(code, 3); self.assertIn('not written by this installer', out)
        self.assertTrue(plist.exists())



class LifecycleBase(InstallerTestCase):
    """Installed and running 0.5.4, plus a reviewed 0.6.0 plan."""

    def setUp(self):
        super().setUp()
        self.install_running()

    def install_running(self):
        self.assertOk(self.install())
        self.host.provision_credentials()
        self.assertOk(self.install())
        self.bundle2 = self.host.bundle('0.6.0')
        self.plan2 = self.host.plan('0.6.0', self.bundle2)

    def upgrade(self, *extra):
        return self.run_installer('upgrade', '--plan', str(self.plan2), '--bundle', str(self.bundle2), *self.pinned(self.plan2), *extra)


class ReviewPinningTests(InstallerTestCase):
    """Review F1: the reviewed plan digest, the installer code and the signer are pinned."""

    def test_install_requires_the_reviewed_plan_digest(self):
        code, _, err = self.run_installer('install', '--plan', str(self.plan1), '--bundle', str(self.bundle1), '--allow-development-signature')
        self.assertEqual(code, 2); self.assertIn('--expect-plan-sha256', err)
        code, _, err = self.run_installer('install', '--plan', str(self.plan1), '--bundle', str(self.bundle1), '--allow-development-signature',
                                          '--expect-plan-sha256', '0' * 64)
        self.assertEqual(code, 2); self.assertIn('changed after review', err)
        self.assertEqual(self.host.mutating_calls(), [])
        self.assertFalse(self.host.path(ROOT).exists())
        self.assertOk(self.install())

    def test_plan_rewritten_after_review_is_refused_even_when_self_consistent(self):
        reviewed = digest(self.plan1)
        # A user-writable plan directory regenerated with other inputs resolves cleanly but is not what was reviewed.
        shutil.rmtree(self.plan1)
        self.host.plan('0.5.4', self.bundle1, human_gid='650')
        code, _, err = self.run_installer('install', '--plan', str(self.plan1), '--bundle', str(self.bundle1),
                                          '--allow-development-signature', '--expect-plan-sha256', reviewed)
        self.assertEqual(code, 2); self.assertIn('changed after review', err)
        self.assertEqual(self.host.mutating_calls(), [])

    def test_signature_policy_is_required_and_pins_the_team(self):
        code, _, err = self.install('--expect-plan-sha256', digest(self.plan1), pin=False)
        self.assertEqual(code, 2); self.assertIn('--allow-development-signature', err)
        self.assertEqual(self.host.mutating_calls(), [])
        # A Developer-ID signed bundle needs --team-id; the development allowance does not cover it.
        app = self.host.bundle('0.6.0', payload_extra=b' TEAM=ABCDE12345')
        plan_dir = self.host.plan('0.6.0', app)
        code, _, err = self.install(plan_dir=plan_dir, bundle=app)
        self.assertEqual(code, 2); self.assertIn('signed by team ABCDE12345; pass --team-id ABCDE12345', err)
        self.assertFalse(self.host.path(f'{ROOT}/versions/0.6.0').exists())
        pin = ['--expect-plan-sha256', digest(plan_dir)]
        code, _, err = self.run_installer('install', '--plan', str(plan_dir), '--bundle', str(app), *pin, '--team-id', 'ZZZZZ99999')
        self.assertEqual(code, 2); self.assertIn('for team ZZZZZ99999', err)
        code, _, err = self.run_installer('install', '--plan', str(plan_dir), '--bundle', str(app), *pin, '--team-id', 'abc')
        self.assertEqual(code, 2); self.assertIn('10 uppercase', err)
        self.assertOk(self.run_installer('install', '--plan', str(plan_dir), '--bundle', str(app), *pin, '--team-id', 'ABCDE12345'))
        requirement = '=anchor apple generic and certificate leaf[subject.OU] = "ABCDE12345"'
        verifies = [c for c in self.host.calls() if c[:2] == ['codesign', '--verify'] and c[-1].endswith('versions/0.6.0/vaultwarden-accessd')]
        self.assertTrue(verifies and all(c[1:5] == ['--verify', '--strict', '-R', requirement] for c in verifies))
        self.assertEqual(self.receipt()['versions']['0.6.0']['signature'], {'team_id': 'ABCDE12345'})
        start = len(self.host.calls())
        self.assertOk(self.run_installer('status'))  # the recorded team requirement is reused, not today's flags
        self.assertIn(['codesign', '--verify', '--strict', '-R', requirement, str(self.host.path(f'{ROOT}/versions/0.6.0/vw-access'))],
                      self.host.calls()[start:])

    def test_ad_hoc_bundle_is_refused_when_a_team_is_required(self):
        code, _, err = self.run_installer('install', '--plan', str(self.plan1), '--bundle', str(self.bundle1),
                                          '--expect-plan-sha256', digest(self.plan1), '--team-id', 'ABCDE12345')
        self.assertEqual(code, 2); self.assertIn('fails codesign', err)

    def test_mutating_runs_refuse_installer_code_writable_by_non_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            top = Path(os.path.realpath(temporary))
            code_dir = top / 'checkout' / 'scripts'
            code_dir.mkdir(parents=True)
            script = code_dir / 'macos-provider-install.py'
            script.write_text('# installer\n')
            os.chmod(top / 'checkout', 0o755); os.chmod(code_dir, 0o755); os.chmod(script, 0o644)
            mine = (0, os.getuid())
            installer.check_code_trust([script], owners=mine, top=top)
            for target, mode in [(script, 0o664), (code_dir, 0o775), (top / 'checkout', 0o757)]:
                with self.subTest(target=target.name):
                    os.chmod(target, mode)
                    with self.assertRaisesRegex(installer.InstallError, 'can be changed by a non-root account'):
                        installer.check_code_trust([script], owners=mine, top=top)
                    os.chmod(target, 0o644 if target == script else 0o755)
            # Owned by a non-root account: refused even without write bits for others.
            with self.assertRaisesRegex(installer.InstallError, 'non-root'):
                installer.check_code_trust([script], owners=(0,), top=top)
            # main() runs the check (with the root-only default) before any mutation.
            with patch.object(installer, 'code_paths', return_value=[script]):
                code, _, err = self.install()
            self.assertEqual(code, 2); self.assertIn('run a root-owned copy of the installer', err)
        self.assertEqual(self.host.mutating_calls(), [])

    def test_mach_o_architecture_is_checked_not_trusted_from_the_manifest(self):
        # Review F14: bundle.json says aarch64, the binary does not.
        for marker, archs in [(b' X86', 'x86_64'), (b' UNIVERSAL', 'x86_64 arm64')]:
            with self.subTest(archs=archs):
                app = self.host.bundle('0.6.0', payload_extra=marker, tag=archs.replace(' ', ''))
                plan_dir = self.host.plan('0.6.0', app, tag=archs.replace(' ', ''))
                code, _, err = self.install(plan_dir=plan_dir, bundle=app)
                self.assertEqual(code, 2); self.assertIn(f'not an arm64-only Mach-O (lipo -archs: {archs})', err)
                self.assertFalse(self.host.path(f'{ROOT}/versions/0.6.0').exists())
                shutil.rmtree(self.host.path(f'{ROOT}/versions/.staging-0.6.0'), ignore_errors=True)
                os.chmod(self.host.path(f'{ROOT}/versions'), 0o755)
        self.assertTrue(any(c[:2] == ['lipo', '-archs'] for c in self.host.calls()))


class RemoveTreeTests(InstallerTestCase):
    """Review F2: removal never follows, chmods or chowns through a symbolic link."""

    def test_symlink_to_an_outside_directory_is_never_followed(self):
        base = self.host.base
        outside = base / 'outside'; outside.mkdir(); (outside / 'keep.txt').write_text('keep')
        os.chmod(outside, 0o755)
        link = base / 'state-link'; link.symlink_to(outside)
        with self.assertRaises((installer.InstallError, OSError)):
            installer.remove_tree(link)
        self.assertEqual(stat.S_IMODE(os.stat(outside).st_mode), 0o755)
        self.assertTrue((outside / 'keep.txt').exists())
        # A link inside the tree (also one replacing a subdirectory) is unlinked, its target untouched.
        tree = base / 'state'; (tree / 'sub').mkdir(parents=True); (tree / 'sub' / 'file').write_text('x')
        (tree / 'escape').symlink_to(outside)
        (tree / 'sub' / 'escape-file').symlink_to(outside / 'keep.txt')
        os.chmod(tree / 'sub', 0o555)
        os.chmod(outside / 'keep.txt', 0o444)
        installer.remove_tree(tree)
        self.assertFalse(os.path.lexists(tree))
        self.assertEqual(stat.S_IMODE(os.stat(outside).st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(os.stat(outside / 'keep.txt').st_mode), 0o444)
        self.assertEqual((outside / 'keep.txt').read_text(), 'keep')

    def test_purge_with_a_link_swapped_into_state_keeps_the_outside_directory(self):
        self.assertOk(self.install())
        outside = self.host.base / 'outside'; outside.mkdir(); (outside / 'secret').write_text('s')
        os.chmod(outside, 0o751)
        (self.host.path(f'{ROOT}/state') / 'audit').symlink_to(outside)
        self.assertOk(self.run_installer('uninstall', '--acknowledge-active-work', '--purge'))
        self.assertFalse(self.host.path(f'{ROOT}/state').exists())
        self.assertEqual(stat.S_IMODE(os.stat(outside).st_mode), 0o751)
        self.assertEqual((outside / 'secret').read_text(), 's')


class AccountRemovalTests(LifecycleBase):
    """Review F3: account removal only when nothing was retained, asserted secret removal, tombstones."""

    def remove_all(self, *extra):
        return self.run_installer('uninstall', '--acknowledge-active-work', '--purge', '--remove-accounts', *extra)

    def test_remove_accounts_requires_the_secret_removal_assertion(self):
        code, _, err = self.remove_all()
        self.assertEqual(code, 2); self.assertIn('--confirm-secrets-removed', err)
        self.assertIn('_vwaccess', self.host.state()['users'])
        self.assertEqual(self.host.state()['launchd']['loaded'], True)

    def test_retained_resources_keep_the_accounts(self):
        (self.host.path(f'{ROOT}/run/human') / 'admin.sock').write_text('')
        code, out, _ = self.remove_all('--confirm-secrets-removed')
        self.assertEqual(code, 3)
        self.assertIn('accounts _vwaccess', out); self.assertIn('not removed: provider resources were retained', out)
        state = self.host.state()
        self.assertIn('_vwaccess', state['users']); self.assertIn('_vwhuman', state['groups'])
        self.assertEqual(self.receipt()['created']['users'], ['_vwaccess'])
        self.assertFalse(self.host.path(f'{ROOT}/account-tombstones.json').exists())

    def test_removed_generated_uid_is_never_reused(self):
        self.assertOk(self.remove_all('--confirm-secrets-removed'))
        tombstones = json.loads(self.host.path(f'{ROOT}/account-tombstones.json').read_text())
        self.assertEqual(tombstones['removed'], [{'name': '_vwaccess', 'uid': 491, 'uuid': PROVIDER_UUID}])
        code, _, err = self.install()
        self.assertEqual(code, 2); self.assertIn('belonged to an account removed by this installer', err)
        self.assertNotIn('_vwaccess', self.host.state()['users'])
        # A new GeneratedUID for the recreated account installs cleanly; the tombstone is kept.
        plan_dir = self.host.plan('0.5.4', self.bundle1, tag='-new-uuid', provider_uuid='1' * 32)
        self.assertOk(self.install(plan_dir=plan_dir))
        self.assertEqual(json.loads(self.host.path(f'{ROOT}/account-tombstones.json').read_text()), tombstones)
        # A second uninstall with nothing installed is a no-op.
        self.assertOk(self.remove_all('--confirm-secrets-removed'))
        self.assertOk(self.remove_all('--confirm-secrets-removed'))


class CrashSafetyTests(InstallerTestCase):
    """Review F4: the receipt is written before each mutation; re-running after a crash converges."""

    def final_state(self):
        users, groups, launchd = self.host.accounts()
        receipt = self.host.path(f'{ROOT}/installer-receipt.json')
        files = [entry for entry in self.host.snapshot()]
        return users, groups, launchd, json.loads(receipt.read_text()) if receipt.exists() else None, files

    def converges(self, prepare, argv_for, reference_steps=None):
        """For every mutation k: crash right after it, re-run the same command, compare with an uninterrupted run."""
        prepare()
        patcher, count = self.crash_after(10 ** 9)
        with patcher:
            self.assertOk(self.run_installer(*argv_for()))
        steps, reference = count[0], self.final_state()
        self.assertGreater(steps, 3)
        for step in range(1, steps + 1):
            with self.subTest(step=step):
                self.fresh_host()
                prepare()
                patcher, _ = self.crash_after(step)
                with patcher, self.assertRaises(Crash):
                    self.run_installer(*argv_for())
                self.assertOk(self.run_installer(*argv_for()))
                self.assertEqual(self.final_state()[:4], reference[:4])
                self.assertEqual([(p, m, d) for p, m, d in self.final_state()[4]], [(p, m, d) for p, m, d in reference[4]])
        return steps

    def test_install_recovers_from_a_crash_after_any_step(self):
        def argv():
            return ['install', '--plan', str(self.plan1), '--bundle', str(self.bundle1), *self.pinned(self.plan1)]
        steps = self.converges(lambda: None, argv)
        self.assertGreater(steps, 30)

    def test_upgrade_recovers_from_a_crash_after_any_step(self):
        def prepare():
            self.assertOk(self.install())
            self.host.provision_credentials()
            self.assertOk(self.install())
            self.bundle2 = self.host.bundle('0.6.0')
            self.plan2 = self.host.plan('0.6.0', self.bundle2)

        def argv():
            return ['upgrade', '--plan', str(self.plan2), '--bundle', str(self.bundle2), *self.pinned(self.plan2), '--acknowledge-active-work']
        self.converges(prepare, argv)
        self.assertEqual(self.receipt()['active_version'], '0.6.0')
        self.assertEqual(self.host.state()['launchd']['program'], f'{ROOT}/versions/0.6.0/vaultwarden-accessd')
        self.assertOk(self.run_installer('status'))

    def test_full_removal_recovers_from_a_crash_after_any_step(self):
        def prepare():
            self.assertOk(self.install())
            self.host.provision_credentials()
            self.assertOk(self.install())

        def argv():
            return ['uninstall', '--acknowledge-active-work', '--purge', '--remove-accounts', '--confirm-secrets-removed']
        self.converges(prepare, argv)
        self.assertNotIn('_vwaccess', self.host.state()['users'])

    def test_receipt_records_a_group_before_creating_it(self):
        seen = []
        tool = installer.Installer.tool

        def spy(instance, name, *args, mutating, check=True):
            if name == 'dseditgroup' and args[:2] == ('-o', 'create'):
                seen.append(json.loads(self.host.path(f'{ROOT}/installer-receipt.json').read_text())['creating']['groups'][-1])
            return tool(instance, name, *args, mutating=mutating, check=check)
        with patch.object(installer.Installer, 'tool', spy):
            self.assertOk(self.install())
        self.assertEqual(seen, ['_vwaccess', '_vwhuman', '_vwagent'])
        self.assertEqual(self.receipt()['creating'], {'users': [], 'groups': []})

    def test_upgrade_records_the_target_before_switching_the_plist(self):
        self.assertOk(self.install())
        self.host.provision_credentials()
        self.assertOk(self.install())
        bundle2 = self.host.bundle('0.6.0'); plan2 = self.host.plan('0.6.0', bundle2)
        seen = []
        write = installer.Installer.write_file

        def spy(instance, destination, *args, **kwargs):
            if destination == installer.DAEMON_PLIST:
                receipt = json.loads(self.host.path(f'{ROOT}/installer-receipt.json').read_text())
                seen.append((sorted(receipt['versions']), receipt.get('switching')))
            return write(instance, destination, *args, **kwargs)
        with patch.object(installer.Installer, 'write_file', spy):
            self.assertOk(self.run_installer('upgrade', '--plan', str(plan2), '--bundle', str(bundle2), *self.pinned(plan2), '--acknowledge-active-work'))
        self.assertEqual(seen, [(['0.5.4', '0.6.0'], {'from': '0.5.4', 'to': '0.6.0'})])
        self.assertNotIn('switching', self.receipt())

    def test_removal_of_already_absent_accounts_is_idempotent(self):
        self.assertOk(self.install())
        self.host.update(lambda s: (s['users'].pop('_vwaccess'), s['groups'].pop('_vwagent')))
        code, out, _ = self.assertOk(self.run_installer('uninstall', '--acknowledge-active-work', '--purge', '--remove-accounts', '--confirm-secrets-removed'))
        self.assertIn('user _vwaccess is already absent', out); self.assertIn('group _vwagent is already absent', out)
        self.assertNotIn('_vwhuman', self.host.state()['groups'])


class RecordedCopyTests(LifecycleBase):
    """Review F5: installed versions are checked against their stored copy and receipt hash, not today's templates."""

    def changed_templates(self):
        build = plan.build

        def drifted(values, templates=plan.TEMPLATES):
            outputs = build(values, templates)
            outputs[plan.PLIST_NAME] = outputs[plan.PLIST_NAME].replace(b'<integer>30</integer>', b'<integer>31</integer>')
            outputs[plan.IDENTITIES_NAME] = outputs[plan.IDENTITIES_NAME].replace(b'"ssh_runtime_dir"', b'"ssh_runtime_dir" ')
            return outputs
        return patch.object(plan, 'build', drifted)

    def test_status_rollback_and_uninstall_survive_a_template_change(self):
        self.assertOk(self.upgrade('--acknowledge-active-work'))
        with self.changed_templates():
            self.assertOk(self.run_installer('status'))
            self.assertOk(self.run_installer('rollback', '--acknowledge-active-work', '--confirm-state-compatible'))
            self.assertEqual(self.host.state()['launchd']['program'], f'{ROOT}/versions/0.5.4/vaultwarden-accessd')
            self.assertOk(self.run_installer('stop', '--acknowledge-active-work'))
            self.assertOk(self.run_installer('start'))
            code, out, _ = self.assertOk(self.run_installer('uninstall', '--acknowledge-active-work'))
        self.assertFalse(self.host.path(f'/Library/LaunchDaemons/{LABEL}.plist').exists())
        self.assertFalse(self.host.path(f'{ROOT}/versions').exists())
        self.assertFalse(self.host.path(f'{ROOT}/native-identities.json').exists())

    def test_a_changed_stored_plist_copy_is_detected(self):
        copy = self.host.path(f'{ROOT}/versions/0.5.4/{LABEL}.plist')
        copy.parent.chmod(0o755); copy.chmod(0o644)
        copy.write_bytes(copy.read_bytes().replace(b'<integer>30</integer>', b'<integer>1</integer>'))
        copy.chmod(0o444); copy.parent.chmod(0o555)
        code, out, _ = self.run_installer('status')
        self.assertEqual(code, 1); self.assertIn('differs from the recorded', out)


class AgentAccountTests(InstallerTestCase):
    """Review F6: the restricted agent account and exact group membership."""

    def setUp(self):
        super().setUp()
        self.agent_plan = self.host.plan('0.5.4', self.bundle1, tag='-agent', agent_account='_vwagent1', agent_uid='602', agent_uuid=AGENT_UUID)

    def test_install_creates_a_hidden_nologin_agent_with_the_agent_primary_group_only(self):
        code, out, _ = self.assertOk(self.install(plan_dir=self.agent_plan))
        state = self.host.state()
        agent = state['users']['_vwagent1']
        self.assertEqual((agent['UniqueID'], agent['PrimaryGroupID'], agent['UserShell'], agent['IsHidden'], agent['Password'], agent['NFSHomeDirectory']),
                         ('602', '601', '/usr/bin/false', '1', '*', '/var/empty'))
        self.assertEqual(agent['GeneratedUID'], installer.generated_uid(AGENT_UUID))
        for group in ['_vwhuman', '_vwaccess', 'admin']:
            self.assertNotIn('_vwagent1', state['groups'][group].get('GroupMembership', '').split())
        self.assertEqual(state['groups']['_vwagent']['GroupMembership'].split(), ['_vwaccess'])
        self.assertEqual(self.receipt()['created']['users'], ['_vwaccess', '_vwagent1'])
        self.assertIn(['dsmemberutil', 'checkmembership', '-U', '_vwagent1', '-G', '_vwagent'], self.host.calls())
        self.assertIn(['dsmemberutil', 'checkmembership', '-U', 'sixto', '-G', '_vwhuman'], self.host.calls())
        self.host.provision_credentials()
        self.assertOk(self.install(plan_dir=self.agent_plan))
        code, out, _ = self.assertOk(self.run_installer('status'))
        self.assertIn('user _vwagent1 (agent): uid 602, primary gid 601', out)
        self.assertIn('group _vwhuman (600): members _vwaccess sixto', out)

    def test_agent_in_a_forbidden_group_is_refused(self):
        self.assertOk(self.install(plan_dir=self.agent_plan))
        self.host.update(lambda s: s['groups']['admin'].__setitem__('GroupMembership', 'root sixto _vwagent1'))
        code, out, _ = self.run_installer('status')
        self.assertEqual(code, 1); self.assertIn('_vwagent1 is a member of admin; a restricted identity must not be', out)
        code, _, err = self.install(plan_dir=self.agent_plan)
        self.assertEqual(code, 2); self.assertIn('_vwagent1 is a member of admin', err)

    def test_adopting_an_agent_checks_shell_hidden_and_groups(self):
        base = {'UniqueID': '602', 'PrimaryGroupID': '601', 'GeneratedUID': installer.generated_uid(AGENT_UUID), 'IsHidden': '1'}
        for label, attrs, message in [('login shell', dict(base, UserShell='/bin/zsh'), 'login shell'),
                                      ('not hidden', dict(base, UserShell='/usr/bin/false', IsHidden='0'), 'not hidden'),
                                      ('wrong primary group', dict(base, UserShell='/usr/bin/false', PrimaryGroupID='20'), 'primary group')]:
            with self.subTest(label):
                self.fresh_host()
                plan_dir = self.host.plan('0.5.4', self.bundle1, tag='-agent', agent_account='_vwagent1', agent_uid='602', agent_uuid=AGENT_UUID)
                self.host.update(lambda s, a=attrs: s['users'].__setitem__('_vwagent1', a))
                code, _, err = self.install('--adopt-existing-accounts', plan_dir=plan_dir)
                self.assertEqual(code, 2); self.assertIn(message, err)
                self.assertEqual(self.host.mutating_calls(), [])

    def test_existing_groups_must_have_exactly_the_planned_members(self):
        self.host.update(lambda s: s['groups'].__setitem__('_vwhuman', {'PrimaryGroupID': '600', 'GroupMembership': 'sixto mallory'}))
        code, _, err = self.install('--adopt-existing-accounts')
        self.assertEqual(code, 2); self.assertIn('members outside the plan (mallory)', err)
        self.assertEqual(self.host.mutating_calls(), [])
        self.host.update(lambda s: s['groups'].pop('_vwhuman'))
        self.assertOk(self.install())
        self.host.update(lambda s: s['groups']['_vwagent'].__setitem__('GroupMembership', '_vwaccess sixto'))
        code, out, _ = self.run_installer('status')
        self.assertEqual(code, 1); self.assertIn("group _vwagent members ['_vwaccess', 'sixto'] differ from the plan ['_vwaccess']", out)

    def test_system_and_low_gid_groups_are_never_adopted(self):
        plan_dir = self.host.plan('0.5.4', self.bundle1, tag='-low', human_gid='450')
        self.host.update(lambda s: s['groups'].__setitem__('_vwhuman', {'PrimaryGroupID': '450'}))
        code, _, err = self.install('--adopt-existing-accounts', plan_dir=plan_dir)
        self.assertEqual(code, 2); self.assertIn('is a system group', err)
        self.assertEqual(self.host.mutating_calls(), [])


class ServiceControlTests(LifecycleBase):
    """Review F7 and F13: launchd state, stop/start, status details and the disable override."""

    def test_status_reports_launchd_state_accounts_sockets_and_credentials(self):
        (self.host.path(f'{ROOT}/run/agent') / 'agent.sock').write_text('')
        code, out, _ = self.run_installer('status')
        self.assertIn(f'service system/{LABEL}: loaded, enabled, state running, pid 4242, last exit code (never exited)', out)
        self.assertIn('user _vwaccess (provider): uid 491, primary gid 491', out)
        self.assertIn('group _vwagent (601): members _vwaccess', out)
        self.assertIn('run/human: no sockets', out)
        self.assertIn('run/agent: agent.sock (not a socket)', out)
        self.assertIn('credentials: present', out)

    def test_start_waits_for_running_and_reports_the_last_exit_code(self):
        self.assertOk(self.run_installer('stop', '--acknowledge-active-work'))
        launchd = self.host.state()['launchd']
        self.assertEqual((launchd['loaded'], launchd['disabled']), (False, True))
        self.host.update(lambda s: s.__setitem__('crash_on_start', True))
        code, _, err = self.run_installer('start')
        self.assertEqual(code, 2)
        self.assertIn('loaded but not running (state not running, last exit code 78)', err)
        code, out, _ = self.run_installer('status')
        self.assertIn('state not running, pid none, last exit code 78', out)
        self.host.update(lambda s: s.pop('crash_on_start'))
        code, out, _ = self.assertOk(self.run_installer('start'))
        self.assertIn('running, pid 4242', out)
        self.assertEqual(self.host.state()['launchd']['running'], True)
        self.assertIn('No changes', self.assertOk(self.run_installer('start'))[1])

    def test_install_does_not_treat_loaded_as_running(self):
        self.assertOk(self.run_installer('stop', '--acknowledge-active-work'))
        self.host.update(lambda s: s.__setitem__('crash_on_start', True))
        code, _, err = self.install()
        self.assertEqual(code, 2); self.assertIn('last exit code 78', err)

    def test_stop_requires_acknowledgement_and_root(self):
        code, _, err = self.run_installer('stop')
        self.assertEqual(code, 2); self.assertIn('--acknowledge-active-work', err)
        with patch.object(installer, 'effective_uid', return_value=501):
            code, _, err = self.run_installer('stop', '--acknowledge-active-work')
        self.assertEqual(code, 2); self.assertIn('must run as root', err)
        self.assertEqual(self.host.state()['launchd']['running'], True)

    def test_uninstall_clears_the_disable_override_and_never_disables_again(self):
        self.assertOk(self.run_installer('uninstall', '--acknowledge-active-work'))
        self.assertEqual(self.host.state()['launchd']['disabled'], False)
        start = len(self.host.calls())
        code, out, _ = self.assertOk(self.run_installer('uninstall', '--acknowledge-active-work'))
        self.assertEqual([c for c in self.host.calls()[start:] if c[0] == 'launchctl' and c[1] in ('disable', 'enable', 'bootout')], [])
        self.assertIn('No changes', out)

    def test_a_retained_foreign_plist_keeps_its_override(self):
        plist = self.host.path(f'/Library/LaunchDaemons/{LABEL}.plist')
        plist.write_bytes(plist.read_bytes().replace(b'127.0.0.1:8443', b'0.0.0.0:8443'))
        code, _, _ = self.run_installer('uninstall', '--acknowledge-active-work')
        self.assertEqual(code, 3)
        self.assertEqual(self.host.state()['launchd']['disabled'], True)


class OperatorGuidanceTests(InstallerTestCase):
    """Review F9: the printed next steps are complete and point at the documentation."""

    def test_next_steps_cover_enrollment_certificates_and_backend_fields(self):
        code, out, _ = self.assertOk(self.install())
        for expected in ['subjectAltName', 'IP:127.0.0.1', 'CLIENT CA', 'server CA (DER), the server leaf pin and its own client PKCS#12',
                         'server (HTTPS origin), client_id, email, encrypted_key', 'kdf_iterations',
                         'stop --acknowledge-active-work',
                         f'sudo install -o _vwaccess -g _vwaccess -m 0600 /path/to/client.pem {ROOT}/state/enroll-client.pem',
                         f'--companion-enroll-cert {ROOT}/state/enroll-client.pem',
                         f'{ROOT}/versions/0.5.4/vw-access --state-root {ROOT}/run/human',
                         'docs/desktop-installation.md#macos-provider-credentials-and-companion-enrollment']:
            self.assertIn(expected, out)
        doc = (HERE.parent / 'docs/desktop-installation.md').read_text()
        self.assertIn('## macOS provider credentials and companion enrollment', doc)
        self.assertNotIn('the Keychain holds\nthe API client secret, the service stays disabled', doc)


class DirectoryServiceOutputTests(InstallerTestCase):
    """Review F11: dscl prints records lacking an attribute as bare names."""

    def test_unrelated_record_without_the_attribute_is_tolerated(self):
        self.host.update(lambda s: s['users'].__setitem__('_halfmade', {'RealName': 'no UniqueID yet'}))
        self.host.update(lambda s: s['groups'].__setitem__('_halfgroup', {'RealName': 'no PrimaryGroupID'}))
        self.assertOk(self.install())

    def test_a_half_created_provider_not_ours_is_refused_clearly(self):
        self.host.update(lambda s: s['users'].__setitem__('_vwaccess', {'RealName': 'someone'}))
        code, _, err = self.install()
        self.assertEqual(code, 2); self.assertIn('user _vwaccess exists without a UniqueID and was not created by this installer', err)
        self.assertEqual(self.host.mutating_calls(), [])

    def test_missing_key_reads_as_absent(self):
        self.assertOk(self.install())
        reader = installer.Installer(self.host.root, True, out=lambda _: None)
        self.assertIsNone(reader.read_attribute('Users', '_vwaccess', 'NoSuchAttribute'))
        self.assertIsNone(reader.read_attribute('Users', 'nobody-here', 'UniqueID'))
        self.assertEqual(reader.users()['_vwaccess'], 491)


class RealProcessToolTests(InstallerTestCase):
    """The fake tools also work as real processes through their shell wrappers."""
    IN_PROCESS = False

    def test_install_through_real_processes(self):
        self.assertOk(self.install())
        self.assertEqual(self.host.state()['users']['_vwaccess']['UniqueID'], '491')


if __name__ == '__main__':
    unittest.main()
