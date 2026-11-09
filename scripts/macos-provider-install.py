#!/usr/bin/env python3
"""Install, upgrade, roll back, remove or inspect the native macOS provider.

Executes exactly a reviewed plan directory written by
scripts/macos-provider-plan.py (with --bundle) and the same arm64 bundle:

  plan       (default) dry run of install: prints every action, changes nothing
  install    accounts, empty secure layout, versioned binaries, LaunchDaemon
  upgrade    verify new version, close admission, bootout, switch, bootstrap
  rollback   switch back to a recorded version with the same order
  uninstall  remove service, plist, versions and identities; keep state,
             Keychain and accounts unless --purge / --remove-accounts
  status     read-only verification of the installed layout and service

Every mutating command also takes --dry-run. Credentials (state/backend.json,
TLS identity, companion CA, Keychain bootstrap secret) are never generated,
copied or deleted: install creates the empty layout and prints the manual
steps. The service is started only when those credentials are present.

Requirements: docs/implementation/issue-49-native-provider.md. Runs with the
system /usr/bin/python3 (3.9) under sudo; standard library only.
"""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True

_spec = importlib.util.spec_from_file_location('macos_provider_plan', Path(__file__).resolve().with_name('macos-provider-plan.py'))
plan = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(plan)

INSTALL_ROOT = plan.INSTALL_ROOT
LABEL = plan.LABEL
SERVICE = f'system/{LABEL}'
DAEMON_PLIST = f'{plan.LAUNCH_DAEMONS}/{plan.PLIST_NAME}'
RECEIPT = f'{INSTALL_ROOT}/{plan.RECEIPT_NAME}'
IDENTITIES = f'{INSTALL_ROOT}/{plan.IDENTITIES_NAME}'
RECEIPT_SCHEMA = 1
KEYCHAIN_SERVICE = 'vaultwarden-accessd'
KEYCHAIN_ACCOUNTS = ('bootstrap-client-secret', 'revocable-session')
MAX_PAYLOAD = 256 * 1024 * 1024
MAX_SMALL = 1024 * 1024
# Absolute system tools. Never resolved through PATH for the real root.
SYSTEM_TOOLS = {
    'dscl': '/usr/bin/dscl',
    'dseditgroup': '/usr/sbin/dseditgroup',
    'launchctl': '/bin/launchctl',
    'chown': '/usr/sbin/chown',
    'stat': '/usr/bin/stat',
    'codesign': '/usr/bin/codesign',
}
FAKE_TOOLS_ENV = 'VW_PROVIDER_INSTALLER_FAKE_TOOLS'
TOOL_ENV = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C', 'LC_ALL': 'C'}
EXIT_REFUSED, EXIT_INCOMPLETE = 2, 3


class InstallError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise InstallError(message)


# Seams for tests; production reads the real process and host.
def effective_uid():
    return os.geteuid()


def host_platform():
    return sys.platform, platform.machine()


def generated_uid(hex32):
    """dscl GeneratedUID form: uppercase with dashes."""
    h = hex32.upper()
    return f'{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}'


def normalize_uuid(text):
    return text.strip().replace('-', '').lower()


def mode_text(mode):
    return '%04o' % mode


class Installer:
    def __init__(self, root, dry_run, out=print):
        self.root = Path(os.path.realpath(str(root)))
        self.dry_run = dry_run
        self.out = out
        self.changes = 0
        self.tools = self._resolve_tools()

    # ---- environment -------------------------------------------------------------------
    def _resolve_tools(self):
        if self.root == Path('/'):
            return dict(SYSTEM_TOOLS)
        fake = os.environ.get(FAKE_TOOLS_ENV)
        require(fake, f'--root other than / is a test prefix and requires fake tools in ${FAKE_TOOLS_ENV}')
        tools = {name: str(Path(fake) / name) for name in SYSTEM_TOOLS}
        for name, path in tools.items():
            require(os.access(path, os.X_OK), f'fake tool missing: {path}')
        return tools

    def fs(self, path):
        """Host path of a documented absolute destination under the root prefix."""
        require(path.startswith('/') and '..' not in path.split('/'), f'invalid destination {path}')
        return self.root / path.lstrip('/')

    def check_ancestors(self, path):
        """No component below the root prefix may be a symbolic link."""
        current = self.root
        for part in Path(path.lstrip('/')).parts:
            current = current / part
            if os.path.lexists(current):
                require(not current.is_symlink(), f'refusing symbolic link at {current}')

    # ---- actions -----------------------------------------------------------------------
    def act(self, description, function=None):
        self.changes += 1
        if self.dry_run:
            self.out(f'would: {description}')
            return None
        self.out(f'+ {description}')
        return function() if function else None

    def tool(self, name, *args, mutating, check=True):
        command = [self.tools[name], *args]
        shown = ' '.join([name, *args])
        if mutating:
            self.changes += 1
            if self.dry_run:
                self.out(f'would run: {shown}')
                return subprocess.CompletedProcess(command, 0, '', '')
            self.out(f'+ {shown}')
        try:
            result = subprocess.run(command, capture_output=True, text=True, env=TOOL_ENV, timeout=120, check=False)
        except (OSError, subprocess.SubprocessError) as error:
            raise InstallError(f'{shown} could not run: {error}') from None
        if check and result.returncode != 0:
            raise InstallError(f'{shown} failed ({result.returncode}): {result.stderr.strip()[:300]}')
        return result

    # ---- directory service -------------------------------------------------------------
    def _list(self, kind, attribute):
        result = self.tool('dscl', '.', '-list', f'/{kind}', attribute, mutating=False)
        records = {}
        for line in result.stdout.splitlines():
            fields = line.split()
            if not fields:
                continue
            require(len(fields) >= 2, f'unexpected dscl output: {line!r}')
            records[fields[0]] = ' '.join(fields[1:])
        return records

    def users(self):
        return {name: int(value) for name, value in self._list('Users', 'UniqueID').items() if value.lstrip('-').isdigit()}

    def groups(self):
        return {name: int(value) for name, value in self._list('Groups', 'PrimaryGroupID').items() if value.lstrip('-').isdigit()}

    def user_uuids(self):
        return {name: normalize_uuid(value) for name, value in self._list('Users', 'GeneratedUID').items()}

    def read_attribute(self, kind, name, attribute):
        result = self.tool('dscl', '.', '-read', f'/{kind}/{name}', attribute, mutating=False, check=False)
        if result.returncode != 0:
            return None
        text = result.stdout.strip()
        prefix = attribute + ':'
        require(text.startswith(prefix), f'unexpected dscl output for {kind}/{name} {attribute}')
        return text[len(prefix):].split()

    def members(self, group):
        return self.read_attribute('Groups', group, 'GroupMembership') or []

    # ---- filesystem --------------------------------------------------------------------
    def owner(self, host_path):
        result = self.tool('stat', '-f', '%u:%g', str(host_path), mutating=False)
        uid, gid = result.stdout.strip().split(':')
        return int(uid), int(gid)

    def chown(self, host_path, uid, gid):
        self.tool('chown', '-h', f'{uid}:{gid}', str(host_path), mutating=False)

    def inspect(self, entry, kind):
        """Problems of one plan entry on disk; [] when it matches. None when absent."""
        path = self.fs(entry['path'])
        self.check_ancestors(entry['path'])
        if not os.path.lexists(path):
            return None
        info = os.lstat(path)
        problems = []
        if path.is_symlink():
            return [f'{entry["path"]} is a symbolic link']
        if kind == 'dir' and not path.is_dir():
            return [f'{entry["path"]} is not a directory']
        if kind == 'file':
            if not path.is_file():
                return [f'{entry["path"]} is not a regular file']
            if info.st_nlink != 1:
                problems.append(f'{entry["path"]} has {info.st_nlink} hard links, expected 1')
        actual_mode = mode_text(info.st_mode & 0o7777)
        if actual_mode != entry['mode']:
            problems.append(f'{entry["path"]} mode {actual_mode}, expected {entry["mode"]}')
        try:
            owner = self.owner(path)
        except InstallError as error:
            problems.append(f'{entry["path"]} owner unreadable: {error}')
        else:
            if owner != (entry['owner_id'], entry['group_id']):
                problems.append(f'{entry["path"]} owner {owner[0]}:{owner[1]}, expected {entry["owner_id"]}:{entry["group_id"]}')
        return problems

    def ensure_dir(self, entry):
        problems = self.inspect(entry, 'dir')
        if problems is None:
            path = self.fs(entry['path'])

            def create():
                os.mkdir(path, 0o700)
                self.chown(path, entry['owner_id'], entry['group_id'])
                os.chmod(path, int(entry['mode'], 8))
            self.act(f'mkdir {entry["path"]} ({entry["owner"]}:{entry["group"]} {entry["mode"]})', create)
            return
        require(not problems, 'existing directory differs from the plan; refusing to change it: ' + '; '.join(problems))

    def write_file(self, destination, data, uid, gid, mode, replace=False):
        path = self.fs(destination)
        self.check_ancestors(destination)

        def write():
            require(path.parent.is_dir(), f'parent of {destination} does not exist')
            require(replace or not os.path.lexists(path), f'{destination} appeared during installation')
            # launchd may read any file in LaunchDaemons: stage the plist on the same
            # volume under the install root instead, then rename it into place.
            staging_parent = self.fs(INSTALL_ROOT) if destination == DAEMON_PLIST else path.parent
            temporary = staging_parent / f'.{path.name}.tmp-{os.getpid()}'
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            descriptor = os.open(temporary, flags, 0o600)
            try:
                with os.fdopen(descriptor, 'wb') as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                self.chown(temporary, uid, gid)
                os.chmod(temporary, mode)
                os.rename(temporary, path)
            except BaseException:
                if os.path.lexists(temporary):
                    os.unlink(temporary)
                raise
            sync_dir(path.parent)
            if staging_parent != path.parent:
                sync_dir(staging_parent)
        self.act(f'write {destination} ({uid}:{gid} {mode_text(mode)}, sha256 {hashlib.sha256(data).hexdigest()})', write)

    def read_payload(self, path):
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, 'rb') as stream:
            data = stream.read(MAX_PAYLOAD + 1)
        require(len(data) <= MAX_PAYLOAD, f'{path} is too large')
        return data

    def read_small(self, path):
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, 'rb') as stream:
            data = stream.read(MAX_SMALL + 1)
        require(len(data) <= MAX_SMALL, f'{path} is too large')
        return data

    # ---- receipt -----------------------------------------------------------------------
    def read_receipt(self):
        path = self.fs(RECEIPT)
        self.check_ancestors(RECEIPT)
        if not os.path.lexists(path):
            return None
        try:
            receipt = json.loads(self.read_small(path))
        except (OSError, ValueError) as error:
            raise InstallError(f'installer receipt unreadable: {error}') from None
        require(isinstance(receipt, dict) and receipt.get('schema') == RECEIPT_SCHEMA and receipt.get('label') == LABEL,
                'installer receipt has an unknown schema')
        return receipt

    def save_receipt(self, receipt):
        data = (json.dumps(receipt, indent=2, sort_keys=True) + '\n').encode()
        self.write_file(RECEIPT, data, 0, 0, 0o644, replace=True)

    # ---- launchd -----------------------------------------------------------------------
    def loaded(self):
        return self.tool('launchctl', 'print', SERVICE, mutating=False, check=False).returncode == 0

    def disabled(self):
        text = self.tool('launchctl', 'print-disabled', 'system', mutating=False, check=False).stdout
        for line in text.splitlines():
            if f'"{LABEL}"' in line:
                return '=> disabled' in line or '=> true' in line
        return False

    def close_admission(self):
        """launchctl disable keeps launchd from loading or restarting the provider."""
        if not self.disabled():
            self.tool('launchctl', 'disable', SERVICE, mutating=True)

    def stop(self):
        if self.loaded():
            # AbandonProcessGroup=true in the plist: consumers survive the provider stop.
            self.tool('launchctl', 'bootout', SERVICE, mutating=True)
            if not self.dry_run:
                require(not self.loaded(), f'{SERVICE} is still loaded after bootout')
        else:
            self.out(f'  {SERVICE} is not loaded')

    def start(self):
        self.tool('launchctl', 'enable', SERVICE, mutating=True)
        try:
            self.tool('launchctl', 'bootstrap', 'system', str(self.fs(DAEMON_PLIST)), mutating=True)
            if not self.dry_run:
                require(self.loaded(), f'{SERVICE} did not load')
        except InstallError as error:
            raise InstallError(f'{error}. The service is not running; inspect with status, and use rollback to '
                               'return to the previous recorded version if needed') from None


def sync_dir(path):
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


# ---- reviewed plan and bundle ----------------------------------------------------------
class Reviewed:
    """A plan directory proven equal to a fresh resolution of its own inputs."""

    def __init__(self, document, values, outputs):
        self.document = document
        self.values = values
        self.outputs = outputs
        self.version = values['version']
        self.directories = document['directories']
        self.files = {entry['path']: entry for entry in document['files']}
        self.binaries = {name: self.files[f'{INSTALL_ROOT}/versions/{self.version}/{name}']['sha256'] for name in plan.BINARIES}

    def identity_inputs(self):
        return {key: value for key, value in self.document['inputs'].items() if key != 'version'}


def load_plan(installer, directory):
    directory = Path(directory)
    require(directory.is_dir() and not directory.is_symlink(), f'plan directory not found: {directory}')
    read = {}
    for name in [plan.PLAN_NAME, plan.PLIST_NAME, plan.IDENTITIES_NAME]:
        try:
            read[name] = installer.read_small(directory / name)
        except OSError as error:
            raise InstallError(f'cannot read {directory / name}: {error}') from None
    try:
        document = json.loads(read[plan.PLAN_NAME])
    except ValueError:
        raise InstallError('plan.json does not parse') from None
    require(isinstance(document, dict) and document.get('schema') == plan.PLAN_SCHEMA,
            f'plan.json schema must be {plan.PLAN_SCHEMA}; regenerate it with scripts/macos-provider-plan.py')
    inputs = document.get('inputs')
    require(isinstance(inputs, dict), 'plan.json has no inputs')
    try:
        values = plan.validate_inputs({key: str(value) for key, value in inputs.items()})
        outputs = plan.build(values)
        hashes = {}
        for entry in document.get('files', []):
            if str(entry.get('source', '')).startswith('bundle:'):
                name = entry['source'].rsplit('/', 1)[-1]
                require(isinstance(entry.get('sha256'), str), 'plan.json lacks bundle hashes; generate it with --bundle')
                hashes[name] = entry['sha256']
        require(sorted(hashes) == sorted(plan.BINARIES), 'plan.json lacks bundle hashes; generate it with --bundle')
        plan.attach_bundle_hashes(outputs, hashes)
    except plan.PlanError as error:
        raise InstallError(f'plan invalid: {error}') from None
    for name in [plan.PLAN_NAME, plan.PLIST_NAME, plan.IDENTITIES_NAME]:
        require(read[name] == outputs[name], f'{name} differs from a fresh resolution of its inputs; regenerate and review the plan')
    return Reviewed(document, values, outputs)


def load_bundle(reviewed, bundle):
    bundle = Path(bundle)
    try:
        hashes = plan.check_bundle(bundle, reviewed.version)
    except plan.PlanError as error:
        raise InstallError(f'bundle invalid: {error}') from None
    require(hashes == reviewed.binaries, 'bundle payload hashes differ from the reviewed plan')
    payloads = {}
    for name in plan.BINARIES:
        path = bundle / plan.BUNDLE_HELPERS / name
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError as error:
            raise InstallError(f'cannot open bundle payload {path}: {error}') from None
        with os.fdopen(descriptor, 'rb') as stream:
            info = os.fstat(stream.fileno())
            require(info.st_nlink == 1, f'bundle payload {path} has {info.st_nlink} hard links, expected 1')
            data = stream.read(MAX_PAYLOAD + 1)
        require(len(data) <= MAX_PAYLOAD, f'bundle payload {path} is too large')
        # The bytes written are the bytes hashed: no re-read between check and copy.
        require(hashlib.sha256(data).hexdigest() == reviewed.binaries[name], f'bundle payload {path} does not match the reviewed hash')
        payloads[name] = data
    return payloads


# ---- accounts --------------------------------------------------------------------------
def account_actions(installer, reviewed, receipt, adopt):
    """Check every account before any write; return the list of creations."""
    values = reviewed.values
    created = (receipt or {}).get('created', {'users': [], 'groups': []})
    adopted = (receipt or {}).get('adopted', {'users': [], 'groups': []})
    users, groups, uuids = installer.users(), installer.groups(), installer.user_uuids()
    users_by_id = {uid: name for name, uid in users.items()}
    groups_by_id = {gid: name for name, gid in groups.items()}
    plan_groups = [(values['provider_group'], values['provider_gid'], 'Vaultwarden Access provider'),
                   (values['human_group'], values['human_gid'], 'Vaultwarden Access human socket'),
                   (values['agent_group'], values['agent_gid'], 'Vaultwarden Access agent socket')]
    create_groups, adopt_groups = [], []
    for name, gid, real_name in plan_groups:
        if name in groups:
            require(groups[name] == gid, f'group {name} exists with GID {groups[name]}, plan requires {gid}')
            if name not in created['groups'] and name not in adopted['groups']:
                require(adopt, f'group {name} already exists and was not created by this installer; pass --adopt-existing-accounts after reviewing it')
                adopt_groups.append(name)
        else:
            require(gid not in groups_by_id, f'GID {gid} is already used by group {groups_by_id.get(gid)}')
            create_groups.append((name, gid, real_name))
    provider, uid, uuid = values['provider_account'], values['provider_uid'], values['provider_uuid']
    create_user, adopt_user = False, False
    if provider in users:
        require(users[provider] == uid, f'user {provider} exists with UID {users[provider]}, plan requires {uid}')
        require(uuids.get(provider) == uuid, f'user {provider} GeneratedUID differs from the plan')
        primary = installer.read_attribute('Users', provider, 'PrimaryGroupID')
        require(primary == [str(values['provider_gid'])], f'user {provider} primary group differs from the plan')
        if provider not in created['users'] and provider not in adopted['users']:
            require(adopt, f'user {provider} already exists and was not created by this installer; pass --adopt-existing-accounts after reviewing it')
            adopt_user = True
    else:
        require(uid not in users_by_id, f'UID {uid} is already used by user {users_by_id.get(uid)}')
        require(uuid not in uuids.values(), 'provider GeneratedUID is already used by another user')
        create_user = True
    operator = users_by_id.get(values['operator_uid'])
    require(operator is not None, f'operator UID {values["operator_uid"]} has no account')
    require(uuids.get(operator) == values['operator_uuid'], f'operator {operator} GeneratedUID differs from the plan')
    require(operator != provider, 'operator and provider accounts must differ')
    memberships = [(provider, values['human_group']), (operator, values['human_group']), (provider, values['agent_group'])]
    return {'create_groups': create_groups, 'adopt_groups': adopt_groups, 'create_user': create_user, 'adopt_user': adopt_user,
            'memberships': memberships, 'operator': operator}


def apply_accounts(installer, reviewed, actions, receipt):
    values = reviewed.values
    for name, gid, real_name in actions['create_groups']:
        installer.tool('dseditgroup', '-o', 'create', '-i', str(gid), '-r', real_name, name, mutating=True)
        receipt['created']['groups'].append(name)
    receipt['adopted']['groups'].extend(actions['adopt_groups'])
    provider = values['provider_account']
    if actions['create_user']:
        record = f'/Users/{provider}'
        installer.tool('dscl', '.', '-create', record, mutating=True)
        receipt['created']['users'].append(provider)
        for attribute, value in [('UniqueID', str(values['provider_uid'])), ('PrimaryGroupID', str(values['provider_gid'])),
                                 ('GeneratedUID', generated_uid(values['provider_uuid'])), ('UserShell', '/usr/bin/false'),
                                 ('NFSHomeDirectory', '/var/empty'), ('RealName', 'Vaultwarden Access provider'),
                                 ('Password', '*'), ('IsHidden', '1')]:
            installer.tool('dscl', '.', '-create', record, attribute, value, mutating=True)
    if actions['adopt_user']:
        receipt['adopted']['users'].append(provider)
    for user, group in actions['memberships']:
        if user not in installer.members(group):
            installer.tool('dseditgroup', '-o', 'edit', '-a', user, '-t', 'user', group, mutating=True)
            if [user, group] not in receipt['memberships_added']:
                receipt['memberships_added'].append([user, group])
    if not installer.dry_run:
        check = account_actions(installer, reviewed, receipt, adopt=False)
        require(not check['create_groups'] and not check['create_user'], 'accounts are not visible after creation')
        for user, group in actions['memberships']:
            require(user in installer.members(group), f'{user} is not a member of {group} after creation')


# ---- versions --------------------------------------------------------------------------
def version_entries(version):
    directory = f'{INSTALL_ROOT}/versions/{version}'
    entries = {f'{directory}/{name}': '0555' for name in plan.BINARIES}
    entries[f'{directory}/{plan.PLIST_NAME}'] = '0444'
    return directory, entries


def verify_version(installer, version, binaries, plist_bytes):
    """Problems of an installed version against its recorded hashes; [] when intact."""
    directory, entries = version_entries(version)
    problems = installer.inspect({'path': directory, 'mode': '0555', 'owner_id': 0, 'group_id': 0}, 'dir')
    if problems is None:
        return [f'{directory} is missing']
    if problems:
        return problems
    names = sorted(os.listdir(installer.fs(directory)))
    expected_names = sorted(Path(p).name for p in entries)
    if names != expected_names:
        return [f'{directory} contains {names}, expected {expected_names}']
    expected = dict({name: digest for name, digest in binaries.items()}, **{plan.PLIST_NAME: hashlib.sha256(plist_bytes).hexdigest()})
    for path, mode in entries.items():
        found = installer.inspect({'path': path, 'mode': mode, 'owner_id': 0, 'group_id': 0}, 'file')
        if found is None:
            problems.append(f'{path} is missing')
            continue
        problems.extend(found)
        if not found:
            digest = hashlib.sha256(installer.read_payload(installer.fs(path))).hexdigest()
            if digest != expected[Path(path).name]:
                problems.append(f'{path} sha256 {digest} differs from the recorded {expected[Path(path).name]}')
    if not problems:
        for name in plan.BINARIES:
            result = installer.tool('codesign', '--verify', '--strict', str(installer.fs(f'{directory}/{name}')), mutating=False, check=False)
            if result.returncode != 0:
                problems.append(f'{directory}/{name} fails codesign --verify --strict')
    return problems


def install_version(installer, reviewed, payloads):
    """Stage a complete verified version and rename it into place. Never overwrites."""
    version = reviewed.version
    directory, _ = version_entries(version)
    plist_bytes = reviewed.outputs[plan.PLIST_NAME]
    target = installer.fs(directory)
    installer.check_ancestors(directory)
    if os.path.lexists(target):
        problems = verify_version(installer, version, reviewed.binaries, plist_bytes)
        require(not problems, f'version {version} already exists and differs; it is never overwritten: ' + '; '.join(problems))
        installer.out(f'  version {version} already installed and verified')
        return False
    staging = installer.fs(f'{INSTALL_ROOT}/versions/.staging-{version}')
    if os.path.lexists(staging):
        allowed = set(plan.BINARIES) | {plan.PLIST_NAME}
        require(staging.is_dir() and not staging.is_symlink() and set(os.listdir(staging)) <= allowed,
                f'unexpected leftover {staging}; inspect and remove it manually')
        installer.act(f'remove leftover staging directory {staging.name}', lambda: remove_tree(staging))

    def stage():
        os.mkdir(staging, 0o700)
        contents = dict(payloads, **{plan.PLIST_NAME: plist_bytes})
        for name, data in contents.items():
            path = staging / name
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            installer.chown(path, 0, 0)
            os.chmod(path, 0o444 if name == plan.PLIST_NAME else 0o555)
        for name in plan.BINARIES:
            installer.tool('codesign', '--verify', '--strict', str(staging / name), mutating=False)
        installer.chown(staging, 0, 0)
        os.chmod(staging, 0o555)
        sync_dir(staging)
        require(not os.path.lexists(target), f'{directory} appeared during staging')
        os.rename(staging, target)
        sync_dir(target.parent)
    for name in plan.BINARIES:
        installer.out(f'  {name}: sha256 {reviewed.binaries[name]} (bundle {plan.BUNDLE_HELPERS}/{name})')
    installer.act(f'install version {version} into {directory} (root:wheel 0555, binaries 0555, plist 0444) via staging and rename', stage)
    if not installer.dry_run:
        problems = verify_version(installer, version, reviewed.binaries, plist_bytes)
        require(not problems, 'installed version failed verification: ' + '; '.join(problems))
    return True


def remove_tree(path):
    """Remove a directory tree without following links (root may lack write bits only in tests)."""
    for current, directories, _ in os.walk(path, followlinks=False):
        for name in directories:
            child = Path(current) / name
            if not child.is_symlink():
                os.chmod(child, 0o700)
    os.chmod(path, 0o700)
    shutil.rmtree(path)


# ---- credentials -----------------------------------------------------------------------
def credential_status(installer, reviewed_files):
    """(complete, [problems]) for the operator-provisioned state files."""
    problems = []
    state = installer.fs(f'{INSTALL_ROOT}/state')
    if os.path.isdir(state) and not os.access(state, os.R_OK | os.X_OK):
        return False, [f'{INSTALL_ROOT}/state is unreadable without root; credentials not checked']
    for entry in reviewed_files.values():
        if entry['created_by'] != 'operator':
            continue
        try:
            found = installer.inspect(entry, 'file')
        except (OSError, InstallError) as error:
            problems.append(f'{entry["path"]} unreadable ({error}); run as root')
            continue
        if found is None:
            problems.append(f'{entry["path"]} is missing')
        else:
            problems.extend(found)
    return not problems, problems


def next_steps(reviewed, operator):
    values = reviewed.values
    account, group, version = values['provider_account'], values['provider_group'], reviewed.version
    state = f'{INSTALL_ROOT}/state'
    lines = [
        'Next manual steps (the installer never generates or copies credentials):',
        f'  1. Provision the backend setup JSON and the companion TLS identity/CA through your approved procedure, then:',
    ]
    for name in plan.STATE_FILES:
        lines.append(f'       sudo install -o {account} -g {group} -m 0600 /path/to/{name} {state}/{name}')
    lines += [
        f'  2. Provision the API client secret in the Keychain the provider account reads: service {KEYCHAIN_SERVICE},',
        '     account bootstrap-client-secret. The Keychain location for a non-login service account is an open',
        '     installed-qualification item (docs/implementation/issue-49-native-provider.md); the installer does not touch it.',
        f'  3. Enroll the companion client certificate as the provider account (service stopped):',
        f'       sudo -u {account} {INSTALL_ROOT}/versions/{version}/vaultwarden-accessd --state-root {state} \\',
        '         --companion-enroll-cert /path/to/client.pem --companion-client-ca ' + f'{state}/companion-ca.pem --companion-label "Mac operator"',
        f'  4. Re-run this installer with the same --plan and --bundle: it starts the service once the files above verify.',
        f'     Restricted agents use {INSTALL_ROOT}/run/agent/agent.sock with their own UID and effective GID {values["agent_gid"]};',
        f'     the operator ({operator}) reaches {INSTALL_ROOT}/run/human through group {values["human_group"]}.',
        '  The provider always starts locked: unlock with a fresh password approval in the companion.',
    ]
    return '\n'.join(lines)


# ---- commands --------------------------------------------------------------------------
def new_receipt(reviewed):
    return {'schema': RECEIPT_SCHEMA, 'label': LABEL, 'inputs': reviewed.identity_inputs(), 'status': 'installed',
            'created': {'users': [], 'groups': []}, 'adopted': {'users': [], 'groups': []}, 'memberships_added': [],
            'versions': {}, 'active_version': None, 'previous_version': None}


def record_version(receipt, reviewed):
    receipt['versions'][reviewed.version] = {'binaries': dict(reviewed.binaries),
                                             'plist_sha256': hashlib.sha256(reviewed.outputs[plan.PLIST_NAME]).hexdigest()}


def check_daemon_plist(installer, allowed):
    """None when absent; True when it equals one of the allowed plists; refusal otherwise."""
    path = installer.fs(DAEMON_PLIST)
    installer.check_ancestors(DAEMON_PLIST)
    if not os.path.lexists(path):
        return None
    require(path.is_file() and not path.is_symlink(), f'{DAEMON_PLIST} is not a regular file')
    data = installer.read_small(path)
    require(data in allowed, f'{DAEMON_PLIST} exists and was not written by this installer for a recorded version; refusing to replace it')
    return data


def plist_for(receipt, version):
    values = plan.validate_inputs(dict({k: str(v) for k, v in receipt['inputs'].items()}, version=version))
    return plan.build(values)[plan.PLIST_NAME]


def command_install(installer, args):
    reviewed = load_plan(installer, args.plan)
    payloads = load_bundle(reviewed, args.bundle)
    require(installer.fs(plan.LAUNCH_DAEMONS).is_dir(), f'{plan.LAUNCH_DAEMONS} does not exist')
    receipt = installer.read_receipt()
    if receipt is not None:
        require(receipt['inputs'] == reviewed.identity_inputs(), 'installed identity (accounts, IDs, groups) differs from this plan; identity changes are not supported')
        active = receipt.get('active_version')
        require(active in (None, reviewed.version), f'version {active} is installed; use upgrade')
    else:
        receipt = new_receipt(reviewed)
    actions = account_actions(installer, reviewed, receipt, args.adopt_existing_accounts)
    identities = installer.fs(IDENTITIES)
    if os.path.lexists(identities):
        require(installer.read_small(identities) == reviewed.outputs[plan.IDENTITIES_NAME], f'{IDENTITIES} exists and differs from the plan')
    plist_bytes = reviewed.outputs[plan.PLIST_NAME]
    existing_plist = check_daemon_plist(installer, [plist_bytes])
    for entry in reviewed.directories:
        problems = installer.inspect(entry, 'dir')
        require(not problems, 'existing directory differs from the plan; refusing to change it: ' + '; '.join(problems or []))
    # All checks passed. Mutations follow in a fail-closed order.
    installer.out(f'Installing native provider {reviewed.version} (label {LABEL}) under {installer.root}')
    installer.ensure_dir(reviewed.directories[0])
    apply_accounts(installer, reviewed, actions, receipt)
    if actions['create_groups'] or actions['create_user'] or actions['adopt_groups'] or actions['adopt_user'] or not os.path.lexists(installer.fs(RECEIPT)):
        installer.save_receipt(receipt)
    for entry in reviewed.directories[1:]:
        if entry['path'] != f'{INSTALL_ROOT}/versions/{reviewed.version}':
            installer.ensure_dir(entry)
    install_version(installer, reviewed, payloads)
    if not os.path.lexists(identities):
        installer.write_file(IDENTITIES, reviewed.outputs[plan.IDENTITIES_NAME], 0, 0, 0o644)
    if reviewed.version not in receipt['versions'] or receipt['active_version'] != reviewed.version or receipt['status'] != 'installed':
        record_version(receipt, reviewed)
        receipt['active_version'] = reviewed.version
        receipt['status'] = 'installed'
        installer.save_receipt(receipt)
    complete, missing = credential_status(installer, reviewed.files)
    loaded = installer.loaded()
    if existing_plist is None:
        if not (complete and not args.no_start):
            installer.close_admission()
        installer.write_file(DAEMON_PLIST, plist_bytes, 0, 0, 0o644)
    if complete and not args.no_start:
        if not loaded:
            installer.start()
        else:
            installer.out(f'  {SERVICE} is loaded')
    else:
        if loaded:
            installer.out(f'  {SERVICE} is loaded; leaving it running')
        else:
            installer.out(f'  service not started: {"--no-start" if args.no_start else "credentials incomplete"}')
            if existing_plist is not None:
                installer.close_admission()
        for problem in missing:
            installer.out(f'  credential: {problem}')
        installer.out(next_steps(reviewed, actions['operator']))
    return 0


def require_acknowledged(installer, args):
    require(installer.dry_run or args.acknowledge_active_work,
            'stopping the provider closes admission; notify the execution owner of active work (the provider never cancels or '
            'kills consumers), then pass --acknowledge-active-work')


def switch(installer, receipt, target, plist_bytes, reviewed_files):
    """Documented order: (verified already) close admission, bootout, switch, bootstrap locked."""
    installer.close_admission()
    installer.stop()
    installer.write_file(DAEMON_PLIST, plist_bytes, 0, 0, 0o644, replace=True)
    receipt['previous_version'], receipt['active_version'] = receipt['active_version'], target
    installer.save_receipt(receipt)
    complete, missing = credential_status(installer, reviewed_files)
    if complete:
        installer.start()
        installer.out(f'  provider {target} started; it starts locked: unlock with a fresh password approval')
    else:
        installer.out(f'  service left disabled: credentials incomplete ({"; ".join(missing)})')


def installed_receipt(installer):
    receipt = installer.read_receipt()
    require(receipt is not None and receipt.get('status') == 'installed' and receipt.get('active_version'),
            'no installation recorded by this installer')
    return receipt


def command_upgrade(installer, args):
    require_acknowledged(installer, args)
    reviewed = load_plan(installer, args.plan)
    payloads = load_bundle(reviewed, args.bundle)
    receipt = installed_receipt(installer)
    active = receipt['active_version']
    require(reviewed.version != active, f'version {active} is already active')
    require(receipt['inputs'] == reviewed.identity_inputs(), 'installed identity differs from this plan; identity changes are not supported')
    allowed = [plist_for(receipt, version) for version in receipt['versions']]
    require(check_daemon_plist(installer, allowed) is not None, f'{DAEMON_PLIST} is missing')
    installer.out(f'Upgrading native provider {active} -> {reviewed.version}')
    # 1. Verify a complete new version before closing admission.
    install_version(installer, reviewed, payloads)
    record_version(receipt, reviewed)
    switch(installer, receipt, reviewed.version, reviewed.outputs[plan.PLIST_NAME], reviewed.files)
    return 0


def command_rollback(installer, args):
    receipt = installed_receipt(installer)
    active = receipt['active_version']
    target = args.to_version or receipt.get('previous_version')
    require(target, 'no previous version recorded; pass --to-version')
    require(target != active, f'version {target} is already active')
    require(target in receipt['versions'], f'version {target} was not installed by this installer')
    plist_bytes = plist_for(receipt, target)
    record = receipt['versions'][target]
    require(record['plist_sha256'] == hashlib.sha256(plist_bytes).hexdigest(), f'recorded plist for {target} does not match its resolution')
    problems = verify_version(installer, target, record['binaries'], plist_bytes)
    require(not problems, f'version {target} failed verification; the current version stays active: ' + '; '.join(problems))
    allowed = [plist_for(receipt, version) for version in receipt['versions']]
    require(check_daemon_plist(installer, allowed) is not None, f'{DAEMON_PLIST} is missing')
    require(installer.dry_run or args.confirm_state_compatible,
            f'roll back only to a version that understands the current native profile, account UUIDs and consumed-request schema; '
            f'consumed approvals are never reactivated. Pass --confirm-state-compatible once {target} is confirmed compatible')
    require_acknowledged(installer, args)
    values = plan.validate_inputs(dict({k: str(v) for k, v in receipt['inputs'].items()}, version=target))
    files = {e['path']: e for e in plan.plan_document(values, plan.build(values))['files']}
    installer.out(f'Rolling back native provider {active} -> {target}')
    switch(installer, receipt, target, plist_bytes, files)
    return 0


def command_uninstall(installer, args):
    require(not args.remove_accounts or args.purge,
            '--remove-accounts requires --purge: a recreated account with the same UID/UUID must never revive retained enrollment')
    receipt = installer.read_receipt()
    require(receipt is not None, 'no installation recorded by this installer')
    require_acknowledged(installer, args)
    # The version only selects the plist; the identity record does not depend on it.
    values = plan.validate_inputs(dict({k: str(v) for k, v in receipt['inputs'].items()}, version=receipt.get('active_version') or '0.0.0'))
    retained = []
    installer.out('Uninstalling native provider (state, Keychain and accounts are preserved unless requested)')
    # Close admission and stop the service first; consumers are never signalled.
    installer.close_admission()
    installer.stop()
    allowed = {plist_for(receipt, version) for version in receipt['versions']}
    daemon = installer.fs(DAEMON_PLIST)
    if os.path.lexists(daemon):
        if daemon.is_file() and not daemon.is_symlink() and installer.read_small(daemon) in allowed:
            installer.act(f'remove {DAEMON_PLIST}', lambda: os.unlink(daemon))
        else:
            retained.append(f'{DAEMON_PLIST} (not written by this installer)')
    for version, record in sorted(receipt['versions'].items()):
        directory = installer.fs(f'{INSTALL_ROOT}/versions/{version}')
        if not os.path.lexists(directory):
            continue
        problems = verify_version(installer, version, record['binaries'], plist_for(receipt, version))
        if problems:
            retained.append(f'{INSTALL_ROOT}/versions/{version} (changed: {"; ".join(problems)})')
        else:
            installer.act(f'remove {INSTALL_ROOT}/versions/{version}', lambda d=directory: remove_tree(d))
    identities = installer.fs(IDENTITIES)
    if os.path.lexists(identities):
        if installer.read_small(identities) == plan.build(values)[plan.IDENTITIES_NAME]:
            installer.act(f'remove {IDENTITIES}', lambda: os.unlink(identities))
        else:
            retained.append(f'{IDENTITIES} (differs from the recorded identity)')
    for relative in ['run/human', 'run/agent', 'run/ssh', 'run', 'versions']:
        remove_empty(installer, f'{INSTALL_ROOT}/{relative}', retained)
    state = installer.fs(f'{INSTALL_ROOT}/state')
    if args.purge and os.path.lexists(state):
        require(state.is_dir() and not state.is_symlink(), f'{INSTALL_ROOT}/state is not a directory')
        installer.act(f'purge {INSTALL_ROOT}/state (provider state, audit history and credential files)', lambda: remove_tree(state))
    elif os.path.lexists(state):
        installer.out(f'  preserved {INSTALL_ROOT}/state')
    installer.out(f'  Keychain items (service {KEYCHAIN_SERVICE}, accounts {", ".join(KEYCHAIN_ACCOUNTS)}) are never deleted by the installer.')
    installer.out('  Remove them manually from the Keychain the provider account used, after reviewing them, if wanted.')
    if args.remove_accounts:
        for user, group in receipt['memberships_added']:
            if user not in receipt['created']['users'] and group not in receipt['created']['groups']:
                installer.tool('dseditgroup', '-o', 'edit', '-d', user, '-t', 'user', group, mutating=True)
        for user in receipt['created']['users']:
            installer.tool('dscl', '.', '-delete', f'/Users/{user}', mutating=True)
        for group in receipt['created']['groups']:
            installer.tool('dseditgroup', '-o', 'delete', group, mutating=True)
        for name in receipt['adopted']['users'] + receipt['adopted']['groups']:
            installer.out(f'  kept adopted account {name} (not created by this installer)')
        receipt['created'] = {'users': [], 'groups': []}
        receipt['memberships_added'] = []
    else:
        names = receipt['created']['users'] + receipt['created']['groups']
        if names:
            installer.out(f'  preserved accounts {", ".join(names)} (pass --purge --remove-accounts to remove them)')
    receipt.update({'status': 'uninstalled', 'versions': {}, 'active_version': None, 'previous_version': None})
    if args.purge and args.remove_accounts and not retained:
        installer.act(f'remove {RECEIPT}', lambda: os.unlink(installer.fs(RECEIPT)))
        remove_empty(installer, INSTALL_ROOT, retained)
    else:
        installer.save_receipt(receipt)
    for item in retained:
        installer.out(f'  retained: {item}')
    if retained:
        installer.out('Removal incomplete: retained resources are listed above; review them before removing anything by hand.')
        return EXIT_INCOMPLETE
    return 0


def remove_empty(installer, destination, retained):
    path = installer.fs(destination)
    if not os.path.lexists(path):
        return
    if path.is_symlink() or not path.is_dir():
        retained.append(f'{destination} (not a directory)')
        return
    contents = os.listdir(path)
    if installer.dry_run:
        installer.act(f'remove {destination} if empty')
    elif contents:
        retained.append(f'{destination} (not empty: {", ".join(sorted(contents)[:5])})')
    else:
        installer.act(f'remove empty {destination}', lambda: os.rmdir(path))


def command_status(installer, args):
    receipt = installer.read_receipt()
    if receipt is None:
        installer.out('not installed by this installer (no receipt)')
        return 1
    active = receipt.get('active_version')
    installer.out(f'receipt: status {receipt.get("status")}, active {active}, previous {receipt.get("previous_version")}, '
                  f'versions {", ".join(sorted(receipt.get("versions", {}))) or "none"}')
    installer.out(f'created accounts: {", ".join(receipt["created"]["users"] + receipt["created"]["groups"]) or "none"}; '
                  f'adopted: {", ".join(receipt["adopted"]["users"] + receipt["adopted"]["groups"]) or "none"}')
    if receipt.get('status') != 'installed' or not active:
        return 1
    values = plan.validate_inputs(dict({k: str(v) for k, v in receipt['inputs'].items()}, version=active))
    outputs = plan.build(values)
    document = plan.plan_document(values, outputs)
    problems = []
    for entry in document['directories']:
        try:
            found = installer.inspect(entry, 'dir')
        except (OSError, InstallError) as error:
            found = [f'{entry["path"]} unreadable: {error}']
        problems.extend([f'{entry["path"]} is missing'] if found is None else found)
    for version, record in sorted(receipt['versions'].items()):
        found = verify_version(installer, version, record['binaries'], plist_for(receipt, version))
        problems.extend(found)
        installer.out(f'version {version}: {"verified" if not found else "FAILED"}')
    for destination, expected in [(IDENTITIES, outputs[plan.IDENTITIES_NAME]), (DAEMON_PLIST, outputs[plan.PLIST_NAME])]:
        entry = next(e for e in document['files'] if e['path'] == destination)
        found = installer.inspect(entry, 'file')
        if found is None:
            problems.append(f'{destination} is missing')
            continue
        problems.extend(found)
        if installer.read_small(installer.fs(destination)) != expected:
            problems.append(f'{destination} differs from the active version {active}')
    complete, missing = credential_status(installer, {e['path']: e for e in document['files']})
    installer.out(f'credentials: {"present" if complete else "incomplete"}')
    for item in missing:
        installer.out(f'  {item}')
    loaded, disabled = installer.loaded(), installer.disabled()
    installer.out(f'service {SERVICE}: {"loaded" if loaded else "not loaded"}, {"disabled" if disabled else "enabled"}')
    for problem in problems:
        installer.out(f'PROBLEM: {problem}')
    return 1 if problems else 0


def parser():
    top = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = top.add_subparsers(dest='command', required=True)

    def add(name, help_text, plan_inputs=False, mutating=True):
        sub = commands.add_parser(name, help=help_text)
        sub.add_argument('--root', default='/', help=argparse.SUPPRESS)
        if plan_inputs:
            sub.add_argument('--plan', required=True, type=Path, help='reviewed plan directory (macos-provider-plan.py --bundle)')
            sub.add_argument('--bundle', required=True, type=Path, help='the same macOS arm64 companion_slice.app')
        if mutating:
            sub.add_argument('--dry-run', action='store_true', help='print every action; change nothing')
        return sub

    for name, text in [('plan', 'dry run of install (default)'), ('install', 'install or complete an installation')]:
        sub = add(name, text, plan_inputs=True, mutating=name == 'install')
        sub.add_argument('--adopt-existing-accounts', action='store_true',
                         help='accept existing accounts/groups that exactly match the plan but were not created by this installer')
        sub.add_argument('--no-start', action='store_true', help='never start the service, even when credentials are present')
    sub = add('upgrade', 'install a new version and switch to it', plan_inputs=True)
    sub.add_argument('--acknowledge-active-work', action='store_true')
    sub = add('rollback', 'switch back to a recorded version')
    sub.add_argument('--to-version')
    sub.add_argument('--confirm-state-compatible', action='store_true')
    sub.add_argument('--acknowledge-active-work', action='store_true')
    sub = add('uninstall', 'remove the service and installer-owned files')
    sub.add_argument('--purge', action='store_true', help='also remove the provider state directory (credentials, audit history)')
    sub.add_argument('--remove-accounts', action='store_true', help='with --purge: remove accounts and groups this installer created')
    sub.add_argument('--acknowledge-active-work', action='store_true')
    add('status', 'verify the installation (read-only)', mutating=False)
    return top


COMMANDS = {'plan': command_install, 'install': command_install, 'upgrade': command_upgrade,
            'rollback': command_rollback, 'uninstall': command_uninstall, 'status': command_status}


def main(argv=None, out=print):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0].startswith('-') and argv[0] not in ('-h', '--help'):
        argv.insert(0, 'plan')
    args = parser().parse_args(argv)
    dry_run = args.command == 'plan' or getattr(args, 'dry_run', False)
    if args.command == 'plan':
        args.no_start = getattr(args, 'no_start', False)
    try:
        system, machine = host_platform()
        require(system == 'darwin' and machine == 'arm64', f'native provider requires macOS on Apple Silicon (arm64); this is {system}/{machine}')
        mutating = args.command not in ('plan', 'status') and not dry_run
        require(not mutating or effective_uid() == 0, f'{args.command} must run as root (sudo); use --dry-run or plan to preview')
        installer = Installer(args.root, dry_run, out)
        lock = None
        if mutating:
            lock = os.open(installer.fs('/Library'), os.O_RDONLY)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise InstallError('another installer run holds the lock') from None
        try:
            code = COMMANDS[args.command](installer, args)
        finally:
            if lock is not None:
                os.close(lock)
    except (InstallError, plan.PlanError) as error:
        print(f'macos-provider-install: {error}', file=sys.stderr)
        return EXIT_REFUSED
    if dry_run:
        out(f'Dry run: {installer.changes} action(s) listed; nothing was changed.')
    elif args.command != 'status' and installer.changes == 0:
        out('No changes: the installation already matches.')
    return code


if __name__ == '__main__':
    sys.exit(main())
