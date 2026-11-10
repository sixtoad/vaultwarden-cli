#!/usr/bin/env python3
"""Install, upgrade, roll back, remove or inspect the native macOS provider.

Executes exactly a reviewed plan directory written by
scripts/macos-provider-plan.py (with --bundle) and the same arm64 bundle:

  plan       (default) dry run of install: prints every action, changes nothing
  install    accounts, empty secure layout, versioned binaries, LaunchDaemon
  upgrade    verify new version, close admission, bootout, switch, bootstrap
  rollback   switch back to a recorded version with the same order
  stop       close admission and boot the service out (consumers keep running)
  start      start the installed active version once its credentials verify
  uninstall  remove service, plist, versions and identities; keep state
             (secrets included) and accounts unless --purge / --remove-accounts
  status     read-only verification of the installed layout, accounts and service

Every mutating command also takes --dry-run. install and upgrade require
--expect-plan-sha256 (the digest of the reviewed plan.json, printed by the plan
generator and by the dry run) and a signature policy (--team-id TEAMID or
--allow-development-signature). Mutating runs refuse unless this script, the
plan module and the templates are root-owned and not writable by any other
account, ancestors included (run a root-owned copy).

Credentials (state/backend.json, TLS identity, companion CA and the provider
secret file store state/secrets/) are never generated, copied or deleted except
by uninstall --purge: install creates the empty layout and prints the manual
steps (docs/macos-setup.md). The service is started only when the four state
files, the stored API client secret and the enrolled companion registry
(state/companion-identities.json) are present with the documented owner, modes
and link count.

Requirements: docs/implementation/issue-49-native-provider.md. Run it as
`sudo /usr/bin/python3 -I <root-owned copy>/scripts/macos-provider-install.py`
(the system Python 3.9, isolated); standard library only.
"""
import os
import sys
# Before any other import: the script's own directory (and the cwd) never shadows a
# standard-library module, even when this file is run as `python3 <path>` as root.
# (os and sys are already loaded by the interpreter's startup, never from sys.path.)
if __name__ == '__main__':
    _shadowing = {os.path.realpath(os.path.dirname(os.path.abspath(__file__))), os.path.realpath(os.getcwd())}
    sys.path[:] = [entry for entry in sys.path if entry and os.path.realpath(entry) not in _shadowing]
    del _shadowing

import argparse
import fcntl
import hashlib
import importlib.util
import json
from pathlib import Path
import platform
import re
import stat
import subprocess
import time

sys.dont_write_bytecode = True

HERE = Path(__file__).resolve().parent
PLAN_PATH = HERE / 'macos-provider-plan.py'
# Mirrors plan.PLIST_TEMPLATE / IDENTITIES_TEMPLATE under plan.TEMPLATES: checked before the
# plan module is executed, and compared with it right after.
TEMPLATE_NAMES = ('com.cantolla.vaultwarden-accessd.plist.in', 'native-identities.json.in')
# Owners allowed for the code that runs as root (and every ancestor directory).
TRUSTED_CODE_OWNERS = (0,)
# Lists a path's access control entries (`ls -led`: mode string with a trailing `+`, then
# one ` N: <entry>` line per ACE). The standard library cannot read ACLs on macOS.
LS_TOOL = '/bin/ls'
LS_ENV = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C', 'LC_ALL': 'C'}
ACL_ENTRY = re.compile(r'\s*\d+: ')
MODE_FIELD = re.compile(r'[-bcdlps][-rwxsStT]{9}([@+]{0,2})$')


class InstallError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise InstallError(message)


def mode_text(mode):
    return '%04o' % mode


def check_code_trust(paths, owners=None, top='/'):
    """Every code file and every ancestor up to top: owned by a trusted owner, no group/other write.

    The plan directory and the bundle are pinned by --expect-plan-sha256 instead
    (decision D16): plan.json carries the plist, identity and binary hashes.
    """
    owners = TRUSTED_CODE_OWNERS if owners is None else owners
    top = Path(os.path.realpath(top))
    seen = set()
    for path in paths:
        current = Path(os.path.realpath(str(path)))
        require(current == top or top in current.parents, f'{current} is outside {top}')
        chain = [current] + [parent for parent in current.parents if parent == top or top in parent.parents]
        for item in chain:
            if item in seen:
                continue
            seen.add(item)
            info = os.lstat(item)
            require(info.st_uid in owners and not info.st_mode & 0o022,
                    f'{item} can be changed by a non-root account (owner uid {info.st_uid}, mode {mode_text(info.st_mode & 0o7777)}); '
                    'run a root-owned copy of the installer (docs/desktop-installation.md#macos-provider-installation-upgrade-and-removal)')
            entries = acl_entries(item)
            require(not entries,
                    f'{item} carries an access control list ({"; ".join(entries)[:200]}), which can grant write access '
                    'beyond its mode; run a root-owned copy of the installer without ACLs (chmod -N)')


def acl_entries(path):
    """The access control entries of one path, read with `ls -led`; fails closed (a pseudo-entry) when unreadable."""
    try:
        result = subprocess.run([LS_TOOL, '-led', str(path)], capture_output=True, text=True, env=LS_ENV, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError) as error:
        return [f'access control list unreadable: {error}']
    lines = result.stdout.splitlines()
    fields = lines[0].split(None, 1) if lines else []
    flags = MODE_FIELD.match(fields[0]) if fields else None
    if result.returncode != 0 or flags is None:
        return [f'access control list unreadable: ls exit {result.returncode} {(result.stderr or result.stdout).strip()[:100]!r}']
    entries = [line.strip() for line in lines[1:] if ACL_ENTRY.match(line)]
    if '+' in flags.group(1) and not entries:
        entries = ['access control list present (+)']
    return entries


def load_plan_module(path=PLAN_PATH, euid=None):
    """Execute the plan module; as root only after this script, it and the templates are proven root-owned."""
    path = Path(path)
    if (os.geteuid() if euid is None else euid) == 0:
        templates = path.resolve().parents[1] / 'packaging/macos/native'
        check_code_trust([Path(__file__).resolve(), path] + [templates / name for name in TEMPLATE_NAMES])
    spec = importlib.util.spec_from_file_location('macos_provider_plan', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    require((module.PLIST_TEMPLATE, module.IDENTITIES_TEMPLATE) == TEMPLATE_NAMES
            and Path(module.TEMPLATES) == path.resolve().parents[1] / 'packaging/macos/native',
            'the plan module names other templates than the installer checks')
    return module


try:
    plan = load_plan_module()
except InstallError as _error:
    if __name__ != '__main__':
        raise
    print(f'macos-provider-install: {_error}', file=sys.stderr)
    sys.exit(2)

INSTALL_ROOT = plan.INSTALL_ROOT
LABEL = plan.LABEL
SERVICE = f'system/{LABEL}'
DAEMON_PLIST = f'{plan.LAUNCH_DAEMONS}/{plan.PLIST_NAME}'
RECEIPT = f'{INSTALL_ROOT}/{plan.RECEIPT_NAME}'
IDENTITIES = f'{INSTALL_ROOT}/{plan.IDENTITIES_NAME}'
TOMBSTONES = f'{INSTALL_ROOT}/{plan.TOMBSTONES_NAME}'
RECEIPT_SCHEMA = 2
TOMBSTONES_SCHEMA = 1
# PR #71: the provider keeps its API client secret in a file store, not the Keychain.
SECRETS_DIR = f'{INSTALL_ROOT}/state/secrets'
BOOTSTRAP_SECRET = f'{SECRETS_DIR}/vaultwarden-accessd.bootstrap-client-secret'
# PR #71 companion_identity::STORE_FILE: `--companion-enroll-cert` writes it; the provider's
# companion listener (identity::enrolled) refuses to bind without it.
COMPANION_STORE = f'{INSTALL_ROOT}/state/companion-identities.json'
MAX_PAYLOAD = plan.MAX_PAYLOAD_BYTES
MAX_SMALL = 1024 * 1024
# Absolute system tools. Never resolved through PATH for the real root.
SYSTEM_TOOLS = {
    'dscl': '/usr/bin/dscl',
    'dseditgroup': '/usr/sbin/dseditgroup',
    'dsmemberutil': '/usr/bin/dsmemberutil',
    'launchctl': '/bin/launchctl',
    'chown': '/usr/sbin/chown',
    'stat': '/usr/bin/stat',
    'codesign': '/usr/bin/codesign',
    'lipo': '/usr/bin/lipo',
}
FAKE_TOOLS_ENV = 'VW_PROVIDER_INSTALLER_FAKE_TOOLS'
TOOL_ENV = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C', 'LC_ALL': 'C'}
EXIT_REFUSED, EXIT_INCOMPLETE = 2, 3
DSCL_RECORD_NOT_FOUND = 56  # eDSRecordNotFound; the only dscl failure that means "no such record"
ADMIN_GROUP = 'admin'
OPERATOR = 'operator'  # plan.json's placeholder for the operator account in group members
MIN_ADOPTABLE_GID = 500
NOLOGIN_SHELLS = ('/usr/bin/false', '/sbin/nologin', '/usr/sbin/nologin')
TEAM_ID = re.compile(r'[A-Z0-9]{10}')
SHA256 = re.compile(r'[0-9a-f]{64}')
# start() waits this long for launchd to report "state = running".
START_WAIT_SECONDS = 10.0
START_POLL_SECONDS = 0.5
DOCS_CREDENTIALS = 'docs/desktop-installation.md#macos-provider-credentials-and-companion-enrollment'
DOCS_SETUP = 'docs/macos-setup.md'


# Seams for tests; production reads the real process and host.
def effective_uid():
    return os.geteuid()


def host_platform():
    return sys.platform, platform.machine()


def code_paths():
    """Files whose content runs as root: this script, the plan module and the templates it resolves."""
    return [Path(__file__).resolve(), Path(plan.__file__).resolve(),
            plan.TEMPLATES / plan.PLIST_TEMPLATE, plan.TEMPLATES / plan.IDENTITIES_TEMPLATE]


def generated_uid(hex32):
    """dscl GeneratedUID form: uppercase with dashes."""
    h = hex32.upper()
    return f'{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}'


def normalize_uuid(text):
    return text.strip().replace('-', '').lower()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


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
        """{record: value or None}. dscl prints a record lacking the attribute as a bare name."""
        result = self.tool('dscl', '.', '-list', f'/{kind}', attribute, mutating=False)
        records = {}
        for line in result.stdout.splitlines():
            fields = line.split(None, 1)
            if fields:
                records[fields[0]] = fields[1].strip() if len(fields) > 1 else None
        return records

    @staticmethod
    def _numbers(records):
        return {name: int(value) if value is not None and value.lstrip('-').isdigit() else None for name, value in records.items()}

    def users(self):
        """{name: UID or None (record without a numeric UniqueID: half-created)}."""
        return self._numbers(self._list('Users', 'UniqueID'))

    def groups(self):
        return self._numbers(self._list('Groups', 'PrimaryGroupID'))

    def user_uuids(self):
        return {name: normalize_uuid(value) for name, value in self._list('Users', 'GeneratedUID').items() if value is not None}

    def read_attribute(self, kind, name, attribute):
        """Values of one attribute; None when the record or the key is missing.

        Real dscl (probed on macOS 26/27 for /Users and /Groups): a record lacking the key
        exits 0 with empty stdout and 'No such key: <attribute>' on stderr; a missing record
        exits 56 (eDSRecordNotFound).
        """
        result = self.tool('dscl', '.', '-read', f'/{kind}/{name}', attribute, mutating=False, check=False)
        if result.returncode == DSCL_RECORD_NOT_FOUND:
            return None
        # Any other failure (directory service unreachable, a killed tool) is not "absent": fail closed.
        require(result.returncode == 0,
                f'dscl . -read /{kind}/{name} {attribute} failed ({result.returncode}): {result.stderr.strip()[:300]}')
        text = result.stdout.strip()
        if not text:
            message = result.stderr.strip()
            require(not message or message.startswith('No such key:'),
                    f'unexpected dscl output for {kind}/{name} {attribute}: {message[:200]!r}')
            return None
        prefix = attribute + ':'
        require(text.startswith(prefix), f'unexpected dscl output for {kind}/{name} {attribute}')
        return text[len(prefix):].split()

    def members(self, group):
        return self.read_attribute('Groups', group, 'GroupMembership') or []

    def is_member(self, user, group):
        """Effective membership as the system resolves it (primary GID and nested groups included)."""
        result = self.tool('dsmemberutil', 'checkmembership', '-U', user, '-G', group, mutating=False, check=False)
        text = result.stdout.strip()
        require(result.returncode == 0 and text in ('user is a member of the group', 'user is not a member of the group'),
                f'dsmemberutil checkmembership {user} {group}: unexpected answer {text or result.stderr.strip()[:200]!r}')
        return text == 'user is a member of the group'

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
        self.act(f'write {destination} ({uid}:{gid} {mode_text(mode)}, sha256 {sha256(data)})', write)

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

    # ---- receipt and tombstones --------------------------------------------------------
    def read_json(self, destination, schema, what):
        path = self.fs(destination)
        self.check_ancestors(destination)
        if not os.path.lexists(path):
            return None
        try:
            document = json.loads(self.read_small(path))
        except (OSError, ValueError) as error:
            raise InstallError(f'{what} unreadable: {error}') from None
        require(isinstance(document, dict) and document.get('schema') == schema and document.get('label') == LABEL,
                f'{what} has an unknown schema')
        problem = (receipt_problem if schema == RECEIPT_SCHEMA and destination == RECEIPT else tombstones_problem)(document)
        require(problem is None, f'{what} {"are" if what.endswith("s") else "is"} malformed ({problem}); inspect {destination} before re-running')
        return document

    def read_receipt(self):
        return self.read_json(RECEIPT, RECEIPT_SCHEMA, 'installer receipt')

    def save_receipt(self, receipt):
        """The receipt is written before (and after) each mutation it records; a dry run writes none."""
        data = encode(receipt)
        path = self.fs(RECEIPT)
        if self.dry_run or (os.path.isfile(path) and not path.is_symlink() and self.read_small(path) == data):
            return
        self.write_file(RECEIPT, data, 0, 0, 0o644, replace=True)

    def read_tombstones(self):
        document = self.read_json(TOMBSTONES, TOMBSTONES_SCHEMA, 'account tombstones')
        return [] if document is None else list(document['removed'])

    def save_tombstones(self, removed):
        self.write_file(TOMBSTONES, encode({'schema': TOMBSTONES_SCHEMA, 'label': LABEL, 'removed': removed}), 0, 0, 0o644, replace=True)

    # ---- launchd -----------------------------------------------------------------------
    def service_info(self):
        """Top-level `key = value` fields of launchctl print; None when the service is not loaded."""
        result = self.tool('launchctl', 'print', SERVICE, mutating=False, check=False)
        if result.returncode != 0:
            return None
        info = {}
        for line in result.stdout.splitlines():
            if line.startswith('\t') and not line.startswith('\t\t') and ' = ' in line:
                key, _, value = line.strip().partition(' = ')
                info.setdefault(key, value)
        return info

    def loaded(self):
        return self.service_info() is not None

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

    def wait_running(self):
        """Loaded is not running: wait for launchd to report the process, else report its last exit."""
        deadline = time.monotonic() + START_WAIT_SECONDS
        while True:
            info = self.service_info()
            if info is not None and info.get('state') == 'running':
                return info
            if time.monotonic() >= deadline:
                break
            time.sleep(START_POLL_SECONDS)
        if info is None:
            raise InstallError(f'{SERVICE} did not load')
        raise InstallError(f'{SERVICE} is loaded but not running (state {info.get("state", "unknown")}, '
                           f'last exit code {info.get("last exit code", "unknown")})')

    def start(self):
        self.tool('launchctl', 'enable', SERVICE, mutating=True)
        try:
            self.tool('launchctl', 'bootstrap', 'system', str(self.fs(DAEMON_PLIST)), mutating=True)
            if not self.dry_run:
                info = self.wait_running()
                self.out(f'  {SERVICE} running, pid {info.get("pid", "unknown")}')
        except InstallError as error:
            raise InstallError(f'{error}. The service is not running; inspect with status, and use rollback to '
                               'return to the previous recorded version if needed') from None


# ---- receipt and tombstone structure ----------------------------------------------------
def _is_str_list(value):
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _is_optional_str(value):
    return value is None or isinstance(value, str)


def _accounts_problem(value, key):
    if not (isinstance(value, dict) and set(value) == {'users', 'groups'} and _is_str_list(value['users']) and _is_str_list(value['groups'])):
        return f'{key} must hold users and groups name lists'
    return None


def _signature_problem(value):
    if value is None or value == {'development': True}:
        return None
    if isinstance(value, dict) and set(value) == {'team_id'} and isinstance(value['team_id'], str) and TEAM_ID.fullmatch(value['team_id']):
        return None
    return 'a version signature must be null, {"development": true} or {"team_id": TEAMID}'


def _version_problem(name, record):
    if not (isinstance(record, dict) and {'binaries', 'plist_sha256', 'signature'} <= set(record)):
        return f'version {name} must record binaries, plist_sha256 and signature'
    binaries = record['binaries']
    if not (isinstance(binaries, dict) and sorted(binaries) == sorted(plan.BINARIES)
            and all(isinstance(v, str) and SHA256.fullmatch(v) for v in binaries.values())):
        return f'version {name} binaries must map {", ".join(plan.BINARIES)} to sha256 digests'
    if not (isinstance(record['plist_sha256'], str) and SHA256.fullmatch(record['plist_sha256'])):
        return f'version {name} plist_sha256 must be a sha256 digest'
    return _signature_problem(record['signature'])


def receipt_problem(document):
    """None for a structurally complete receipt; else the first problem found."""
    required = {'inputs': dict, 'status': str, 'identities_sha256': str, 'created': dict, 'adopted': dict,
                'memberships_added': list, 'versions': dict}
    for key, kind in required.items():
        if not isinstance(document.get(key), kind):
            return f'{key} must be a {kind.__name__}'
    if document['status'] not in ('installed', 'uninstalled'):
        return 'status must be installed or uninstalled'
    if not all(isinstance(k, str) and isinstance(v, (str, int)) and not isinstance(v, bool) for k, v in document['inputs'].items()):
        return 'inputs must map names to strings or integers'
    for key in ('created', 'adopted') + (('creating',) if 'creating' in document else ()):
        problem = _accounts_problem(document[key], key)
        if problem:
            return problem
    if not all(isinstance(pair, list) and len(pair) == 2 and _is_str_list(pair) for pair in document['memberships_added']):
        return 'memberships_added must be [user, group] pairs'
    for name, record in document['versions'].items():
        problem = _version_problem(name, record)
        if problem:
            return problem
    for key in ('active_version', 'previous_version'):
        if not _is_optional_str(document.get(key)):
            return f'{key} must be a version or null'
    if document['status'] == 'installed' and document.get('active_version') not in (None, *document['versions']):
        return 'active_version is not a recorded version'
    for key in ('switching', 'last_switch'):
        if key in document:
            pending = document[key]
            if not (isinstance(pending, dict) and {'from', 'to'} <= set(pending) <= {'from', 'to', 'by'}
                    and _is_optional_str(pending['from']) and isinstance(pending['to'], str)
                    and pending.get('by', 'upgrade') in ('upgrade', 'rollback')):
                return f'{key} must record from, to and by'
    if 'switching' in document and document['switching']['to'] not in document['versions']:
        return 'switching must name a recorded target version'
    return None


def tombstones_problem(document):
    removed = document.get('removed')
    if not isinstance(removed, list):
        return 'removed must be a list'
    for entry in removed:
        if not (isinstance(entry, dict) and set(entry) == {'name', 'uid', 'uuid'} and isinstance(entry['name'], str)
                and isinstance(entry['uid'], int) and not isinstance(entry['uid'], bool)
                and isinstance(entry['uuid'], str) and plan.UUID.fullmatch(entry['uuid'])):
            return 'each removed account must record name, numeric uid and a 32-hex uuid'
    return None


def encode(document):
    return (json.dumps(document, indent=2, sort_keys=True) + '\n').encode()


def sync_dir(path):
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


# ---- reviewed plan and bundle ----------------------------------------------------------
class Reviewed:
    """A plan directory proven equal to a fresh resolution of its own inputs."""

    def __init__(self, document, values, outputs, plan_sha256):
        self.document = document
        self.values = values
        self.outputs = outputs
        self.plan_sha256 = plan_sha256
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
        values = plan.validate_inputs({key: str(value) for key, value in inputs.items() if value is not None})
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
    return Reviewed(document, values, outputs, sha256(read[plan.PLAN_NAME]))


def check_plan_digest(installer, reviewed, args):
    """The human pins the reviewed plan.json; the plan directory itself may be user-writable."""
    expected = getattr(args, 'expect_plan_sha256', None)
    installer.out(f'plan.json sha256: {reviewed.plan_sha256}')
    if expected is None:
        require(installer.dry_run, 'pass --expect-plan-sha256 with the digest of the plan.json you reviewed '
                                   '(printed by macos-provider-plan.py and by the dry run)')
        installer.out(f'  after reviewing plan.json, pass --expect-plan-sha256 {reviewed.plan_sha256}')
        return
    require(SHA256.fullmatch(expected.lower()) is not None, '--expect-plan-sha256 must be 64 hexadecimal digits')
    require(expected.lower() == reviewed.plan_sha256, 'plan.json differs from --expect-plan-sha256: the plan changed after review; refusing')


def signature_policy(args, required):
    team, development = getattr(args, 'team_id', None), getattr(args, 'allow_development_signature', False)
    require(not (team and development), 'pass either --team-id or --allow-development-signature, not both')
    if team:
        require(TEAM_ID.fullmatch(team) is not None, '--team-id must be 10 uppercase letters or digits')
        return {'team_id': team}
    if development:
        return {'development': True}
    require(not required, 'choose the signature policy: --team-id TEAMID for an Apple-issued (Developer ID) signature, or '
                          '--allow-development-signature for an ad-hoc development build')
    return None


def designated_requirement(team):
    """Apple's Developer ID requirement for one team: the Developer ID CA (intermediate marker
    1.2.840.113635.100.6.2.6) and a Developer ID Application leaf (1.2.840.113635.100.6.1.13)."""
    require(isinstance(team, str) and TEAM_ID.fullmatch(team) is not None, 'team identifier must be 10 uppercase letters or digits')
    return ('=anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and '
            f'certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "{team}"')


def binary_problems(installer, path, policy):
    """Architecture and signature of one installed or staged binary (a root-owned copy)."""
    problems = []
    archs = installer.tool('lipo', '-archs', str(path), mutating=False, check=False)
    found = archs.stdout.split()
    if archs.returncode != 0 or found != ['arm64']:
        problems.append(f'{path} is not an arm64-only Mach-O (lipo -archs: {" ".join(found) or archs.stderr.strip()[:120]})')
    if policy is None:
        return problems + [f'{path}: no signature policy recorded']
    team = policy.get('team_id')
    arguments = ['--verify', '--strict'] + (['-R', designated_requirement(team)] if team else [])
    if installer.tool('codesign', *arguments, str(path), mutating=False, check=False).returncode != 0:
        problems.append(f'{path} fails codesign --verify --strict' + (f' for team {team}' if team else ''))
    elif not team:
        info = installer.tool('codesign', '-d', '--verbose=2', str(path), mutating=False, check=False)
        teams = [line.split('=', 1)[1].strip() for line in (info.stdout + '\n' + info.stderr).splitlines() if line.startswith('TeamIdentifier=')]
        if info.returncode != 0:
            problems.append(f'{path}: codesign -d failed')
        elif any(value != 'not set' for value in teams):
            problems.append(f'{path} is signed by team {teams[0]}; pass --team-id {teams[0]} (development signatures are '
                            'only accepted for ad-hoc builds)')
    return problems


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
        require(sha256(data) == reviewed.binaries[name], f'bundle payload {path} does not match the reviewed hash')
        payloads[name] = data
    return payloads


# ---- accounts --------------------------------------------------------------------------
def plan_users(values):
    users = [{'name': values['provider_account'], 'uid': values['provider_uid'], 'uuid': values['provider_uuid'],
              'primary_gid': values['provider_gid'], 'real_name': 'Vaultwarden Access provider', 'role': 'provider'}]
    if 'agent_account' in values:
        users.append({'name': values['agent_account'], 'uid': values['agent_uid'], 'uuid': values['agent_uuid'],
                      'primary_gid': values['agent_gid'], 'real_name': 'Vaultwarden Access restricted agent', 'role': 'agent'})
    return users


def plan_groups(values, operator):
    """(name, gid, real name, exact explicit members). Agents belong to the agent group by primary GID only."""
    provider = values['provider_account']
    return [(values['provider_group'], values['provider_gid'], 'Vaultwarden Access provider', set()),
            (values['human_group'], values['human_gid'], 'Vaultwarden Access human socket', {provider, operator}),
            (values['agent_group'], values['agent_gid'], 'Vaultwarden Access agent socket', {provider})]


def forbidden_memberships(values):
    pairs = [(values['provider_account'], ADMIN_GROUP)]
    for user in plan_users(values):
        if user['role'] == 'agent':
            pairs += [(user['name'], group) for group in (values['human_group'], values['provider_group'], ADMIN_GROUP)]
    return pairs


def required_memberships(values, operator):
    pairs = [(values['provider_account'], values['human_group']), (operator, values['human_group']),
             (values['provider_account'], values['agent_group'])]
    return pairs + [(user['name'], values['agent_group']) for user in plan_users(values) if user['role'] == 'agent']


def user_attributes(user):
    return [('UniqueID', str(user['uid'])), ('PrimaryGroupID', str(user['primary_gid'])), ('GeneratedUID', generated_uid(user['uuid'])),
            ('UserShell', plan.NOLOGIN_SHELL), ('NFSHomeDirectory', '/var/empty'), ('RealName', user['real_name']),
            ('Password', '*'), ('IsHidden', '1')]


def receipt_accounts(receipt):
    receipt.setdefault('creating', {'users': [], 'groups': []})
    return receipt['created'], receipt['creating'], receipt['adopted']


def account_actions(installer, values, receipt, adopt, tombstones=()):
    """Check every account and membership before any write; return what to create, finish or adopt."""
    created, creating, adopted = receipt_accounts(receipt)
    users, groups, uuids = installer.users(), installer.groups(), installer.user_uuids()
    users_by_id = {uid: name for name, uid in users.items() if uid is not None}
    groups_by_id = {gid: name for name, gid in groups.items() if gid is not None}
    operator = users_by_id.get(values['operator_uid'])
    require(operator is not None, f'operator UID {values["operator_uid"]} has no account')
    require(uuids.get(operator) == values['operator_uuid'], f'operator {operator} GeneratedUID differs from the plan')
    require(operator != values['provider_account'], 'operator and provider accounts must differ')
    actions = {'create_groups': [], 'finish_groups': [], 'adopt_groups': [], 'create_users': [], 'finish_users': [],
               'adopt_users': [], 'operator': operator}
    for name, gid, real_name, _ in plan_groups(values, operator):
        if name in groups:
            if name in creating['groups']:
                # Half-created by an interrupted run: finish it, never take over a different identity.
                require(groups[name] in (None, gid), f'group {name} was being created but has GID {groups[name]}; inspect it')
                require(groups_by_id.get(gid, name) == name, f'GID {gid} is already used by group {groups_by_id.get(gid)}')
                actions['finish_groups'].append((name, gid, real_name))
                continue
            require(groups[name] is not None, f'group {name} exists without a PrimaryGroupID and was not created by this installer; inspect it')
            require(groups[name] == gid, f'group {name} exists with GID {groups[name]}, plan requires {gid}')
            if name not in created['groups'] and name not in adopted['groups']:
                require(adopt, f'group {name} already exists and was not created by this installer; pass --adopt-existing-accounts after reviewing it')
                require(gid >= MIN_ADOPTABLE_GID and name not in plan.WELL_KNOWN_NAMES,
                        f'group {name} (GID {gid}) is a system group (GID below {MIN_ADOPTABLE_GID} or a well-known name); '
                        'refusing to adopt it')
                actions['adopt_groups'].append(name)
        else:
            require(gid not in groups_by_id, f'GID {gid} is already used by group {groups_by_id.get(gid)}')
            actions['create_groups'].append((name, gid, real_name))
    removed = {entry.get('uuid') for entry in tombstones}
    for user in plan_users(values):
        name, uid, uuid = user['name'], user['uid'], user['uuid']
        require(uuid not in removed, f'the GeneratedUID planned for {name} belonged to an account removed by this installer '
                                     f'({TOMBSTONES}); choose a new GeneratedUID')
        if name in users:
            if name in creating['users']:
                require(users[name] in (None, uid) and uuids.get(name) in (None, uuid), f'user {name} was being created but differs from the plan; inspect it')
                require(users_by_id.get(uid, name) == name, f'UID {uid} is already used by user {users_by_id.get(uid)}')
                actions['finish_users'].append(user)
                continue
            require(users[name] is not None, f'user {name} exists without a UniqueID and was not created by this installer; inspect it')
            require(users[name] == uid, f'user {name} exists with UID {users[name]}, plan requires {uid}')
            require(uuids.get(name) == uuid, f'user {name} GeneratedUID differs from the plan')
            primary = installer.read_attribute('Users', name, 'PrimaryGroupID')
            require(primary == [str(user['primary_gid'])], f'user {name} primary group differs from the plan')
            if name not in created['users'] and name not in adopted['users']:
                require(adopt, f'user {name} already exists and was not created by this installer; pass --adopt-existing-accounts after reviewing it')
                shell = installer.read_attribute('Users', name, 'UserShell') or []
                require(shell[:1] and shell[0] in NOLOGIN_SHELLS, f'user {name} has a login shell; refusing to adopt it')
                if user['role'] == 'agent':
                    require(installer.read_attribute('Users', name, 'IsHidden') == ['1'], f'agent account {name} is not hidden; refusing to adopt it')
                actions['adopt_users'].append(name)
        else:
            require(uid not in users_by_id, f'UID {uid} is already used by user {users_by_id.get(uid)}')
            require(uuid not in uuids.values(), f'the GeneratedUID planned for {name} is already used by another user')
            actions['create_users'].append(user)
    # Exact membership: an existing group must not carry members outside the plan.
    for name, gid, _, members in plan_groups(values, operator):
        if groups.get(name) is not None:
            extra = set(installer.members(name)) - members
            require(not extra, f'group {name} has members outside the plan ({", ".join(sorted(extra))}); refusing')
    for user, group in forbidden_memberships(values):
        if users.get(user) is not None and groups.get(group) is not None:
            require(not installer.is_member(user, group), f'{user} is a member of {group}; a restricted identity must not be')
    actions['memberships'] = [(user, group) for name, _, _, members in plan_groups(values, operator) for user, group in
                              [(member, name) for member in sorted(members)]]
    return actions


def apply_accounts(installer, values, actions, receipt):
    created, creating, adopted = receipt_accounts(receipt)

    def mark(kind, name, source, target):
        if source is not None and name in source[kind]:
            source[kind].remove(name)
        if target is not None and name not in target[kind]:
            target[kind].append(name)
        installer.save_receipt(receipt)
    # Plan order, whether a group is new or finished after an interrupted run: the receipt stays stable.
    for name, gid, real_name in sorted(actions['create_groups'] + actions['finish_groups'],
                                       key=lambda group: [g[0] for g in plan_groups(values, actions['operator'])].index(group[0])):
        if (name, gid, real_name) in actions['create_groups']:
            mark('groups', name, None, creating)
            installer.tool('dseditgroup', '-o', 'create', '-i', str(gid), '-r', real_name, name, mutating=True)
        elif installer.groups().get(name) is None:
            installer.tool('dscl', '.', '-create', f'/Groups/{name}', 'PrimaryGroupID', str(gid), mutating=True)
        mark('groups', name, creating, created)
    if actions['adopt_groups']:
        adopted['groups'].extend(actions['adopt_groups'])
        installer.save_receipt(receipt)
    for user in [u for u in plan_users(values) if u in actions['create_users'] or u in actions['finish_users']]:
        record = f'/Users/{user["name"]}'
        if user in actions['create_users']:
            mark('users', user['name'], None, creating)
            installer.tool('dscl', '.', '-create', record, mutating=True)
        for attribute, value in user_attributes(user):
            installer.tool('dscl', '.', '-create', record, attribute, value, mutating=True)
        mark('users', user['name'], creating, created)
    if actions['adopt_users']:
        adopted['users'].extend(actions['adopt_users'])
        installer.save_receipt(receipt)
    for user, group in actions['memberships']:
        if user not in installer.members(group):
            if [user, group] not in receipt['memberships_added']:
                receipt['memberships_added'].append([user, group])
                installer.save_receipt(receipt)
            installer.tool('dseditgroup', '-o', 'edit', '-a', user, '-t', 'user', group, mutating=True)
    if not installer.dry_run:
        # opendirectoryd caches membership: flush it so the checks below see the new records.
        installer.tool('dsmemberutil', 'flushcache', mutating=False)
        check = account_actions(installer, values, receipt, adopt=False)
        require(not (check['create_groups'] or check['create_users'] or check['finish_groups'] or check['finish_users']),
                'accounts are not visible after creation')
        for user, group in required_memberships(values, actions['operator']):
            require(installer.is_member(user, group), f'{user} is not a member of {group} after creation')


# ---- versions --------------------------------------------------------------------------
def version_entries(version):
    directory = f'{INSTALL_ROOT}/versions/{version}'
    entries = {f'{directory}/{name}': '0555' for name in plan.BINARIES}
    entries[f'{directory}/{plan.PLIST_NAME}'] = '0444'
    return directory, entries


def version_record(reviewed, policy):
    return {'binaries': dict(reviewed.binaries), 'plist_sha256': sha256(reviewed.outputs[plan.PLIST_NAME]), 'signature': policy}


def verify_version(installer, version, record):
    """Problems of an installed version against its receipt record; [] when intact."""
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
    expected = dict(record['binaries'], **{plan.PLIST_NAME: record['plist_sha256']})
    for path, mode in entries.items():
        found = installer.inspect({'path': path, 'mode': mode, 'owner_id': 0, 'group_id': 0}, 'file')
        if found is None:
            problems.append(f'{path} is missing')
            continue
        problems.extend(found)
        if not found:
            digest = sha256(installer.read_payload(installer.fs(path)))
            if digest != expected[Path(path).name]:
                problems.append(f'{path} sha256 {digest} differs from the recorded {expected[Path(path).name]}')
    if not problems:
        for name in plan.BINARIES:
            problems.extend(binary_problems(installer, installer.fs(f'{directory}/{name}'), record.get('signature')))
    return problems


def stored_plist(installer, version):
    """The versioned plist copy; callers verify it against the receipt first (verify_version)."""
    return installer.read_small(installer.fs(f'{INSTALL_ROOT}/versions/{version}/{plan.PLIST_NAME}'))


def install_version(installer, reviewed, payloads, policy):
    """Stage a complete verified version and rename it into place. Never overwrites."""
    version = reviewed.version
    directory, _ = version_entries(version)
    plist_bytes = reviewed.outputs[plan.PLIST_NAME]
    target = installer.fs(directory)
    installer.check_ancestors(directory)
    record = version_record(reviewed, policy)
    if os.path.lexists(target):
        if policy is None:
            installer.out(f'  version {version} exists; its signature is verified once a policy is chosen')
            return False
        problems = verify_version(installer, version, record)
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
            problems = binary_problems(installer, staging / name, policy)
            require(not problems, 'staged binary failed verification: ' + '; '.join(problems))
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
        problems = verify_version(installer, version, record)
        require(not problems, 'installed version failed verification: ' + '; '.join(problems))
    return True


def remove_tree(path):
    """Remove a directory tree without following any symbolic link.

    Every directory is opened with O_NOFOLLOW and handled through its descriptor
    (fchmod, unlinkat, rmdir relative to it), so a link swapped into the tree is
    only ever unlinked, never followed, chmodded or chowned through.
    """
    path = Path(path)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        require(stat.S_ISDIR(info.st_mode), f'refusing to remove {path}: not a real directory')
        _remove_directory(parent, path.name, info)
    finally:
        os.close(parent)


def _remove_directory(parent, name, info):
    descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        opened = os.fstat(descriptor)
        require((opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino), f'{name} changed during removal')
        # Only through the descriptor of the real directory (root may lack write bits only in tests).
        os.fchmod(descriptor, 0o700)
        with os.scandir(descriptor) as entries:
            names = [entry.name for entry in entries]
        for child in names:
            child_info = os.stat(child, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISDIR(child_info.st_mode):
                _remove_directory(descriptor, child, child_info)
            else:
                os.unlink(child, dir_fd=descriptor)
    finally:
        os.close(descriptor)
    os.rmdir(name, dir_fd=parent)


# ---- credentials -----------------------------------------------------------------------
def layout(values):
    """Directories and files of the documented layout. Paths and modes only: never templates' bytes."""
    return plan.plan_document(values, {plan.PLIST_NAME: b'', plan.IDENTITIES_NAME: b''})


def layout_files(values):
    return {entry['path']: entry for entry in layout(values)['files']}


def credential_status(installer, files):
    """(complete, [problems]) for the operator-provisioned state files."""
    problems = []
    state = installer.fs(f'{INSTALL_ROOT}/state')
    if os.path.isdir(state) and not os.access(state, os.R_OK | os.X_OK):
        return False, [f'{INSTALL_ROOT}/state is unreadable without root; credentials not checked']
    for entry in files.values():
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
    problems.extend(secret_store_problems(installer, files))
    problems.extend(companion_store_problems(installer, files))
    return not problems, problems


def provider_ids(files):
    owner = next(entry for entry in files.values() if entry['created_by'] == 'operator')
    return {'owner': owner['owner'], 'group': owner['group'], 'owner_id': owner['owner_id'], 'group_id': owner['group_id']}


def companion_store_problems(installer, files):
    """Review round 3: the service starts only once a companion is enrolled.

    PR #71 `identity::enrolled()` reads state/companion-identities.json (provider-owned,
    0600, one link, no ACL) before the companion listener binds; without it the provider
    exits and launchd would restart it in a loop.
    """
    try:
        found = installer.inspect(dict(provider_ids(files), path=COMPANION_STORE, mode='0600'), 'file')
    except (OSError, InstallError) as error:
        return [f'{COMPANION_STORE} unreadable ({error}); run as root']
    if found is None:
        return [f'{COMPANION_STORE} is missing (enroll the companion with --companion-enroll-cert while the service is '
                f'stopped, {DOCS_CREDENTIALS})']
    return found


def secret_store_problems(installer, files):
    """Decision R2-8: the service starts only once the provider stored its API client secret.

    The store (written by `vaultwarden-accessd --store-bootstrap-secret`, PR #71) is the
    provider-owned 0700 state/secrets/ with the single-link 0600 bootstrap record; the
    provider re-checks it (and refuses ACLs) at every read. Without it the provider fails
    closed and launchd would restart it in a loop.
    """
    ids = provider_ids(files)
    for path, kind, mode in [(SECRETS_DIR, 'dir', '0700'), (BOOTSTRAP_SECRET, 'file', '0600')]:
        try:
            found = installer.inspect(dict(ids, path=path, mode=mode), kind)
        except (OSError, InstallError) as error:
            return [f'{path} unreadable ({error}); run as root']
        if found is None:
            return [f'{path} is missing (store it with --store-bootstrap-secret, {DOCS_SETUP})']
        if found:
            return found
    return []


def next_steps(values, version, operator):
    account, group = values['provider_account'], values['provider_group']
    state, vdir = f'{INSTALL_ROOT}/state', f'{INSTALL_ROOT}/versions/{version}'
    command = 'sudo /usr/bin/python3 -I <root-owned installer copy>/scripts/macos-provider-install.py'
    lines = [
        f'Next manual steps ({DOCS_SETUP}; the installer never generates or copies credentials; summary: {DOCS_CREDENTIALS}):',
        f'  1. As the operator: {vdir}/vw-access setup tls --out-dir ~/vw-setup/tls --server-ip 127.0.0.1 --client-name "Mac operator"',
        '     (server identity with subjectAltName IP:127.0.0.1, a separate companion client CA, the companion PKCS#12).',
        f'  2. As the operator: {vdir}/vw-access setup backend-json --from-cli-login --kdf pbkdf2 '
        "--kdf-iterations <your account's PBKDF2 iterations> --out ~/vw-setup/backend.json",
        '     (the iteration count is in the web vault under Settings > Security > Keys; Argon2id accounts are refused;',
        '     fields server (HTTPS origin), client_id, email, encrypted_key and kdf_iterations; no secrets).',
        '     Install each state file provider-owned, 0600, one link:',
    ]
    sources = {'backend.json': '~/vw-setup/backend.json'}
    lines += [f'       sudo install -o {account} -g {group} -m 0600 {sources.get(name, "~/vw-setup/tls/" + name)} {state}/{name}'
              for name in plan.STATE_FILES]
    lines += [
        f'  3. API client secret, prompted without echo into the provider file store {BOOTSTRAP_SECRET}:',
        f'       cd / && sudo -u {account} {vdir}/vaultwarden-accessd --state-root {state} --store-bootstrap-secret',
        '  4. Enroll the companion client certificate with the service stopped (the PEM must be provider-owned 0600):',
        f'       {command} stop --acknowledge-active-work',
        f'       sudo install -o {account} -g {group} -m 0600 ~/vw-setup/tls/companion-client.pem {state}/companion-client.pem',
        f'       cd / && sudo -u {account} {vdir}/vaultwarden-accessd --state-root {state} --companion-enroll-cert {state}/companion-client.pem \\',
        f'         --companion-client-ca {state}/companion-ca.pem --companion-label "Mac operator"',
        f'       sudo rm {state}/companion-client.pem',
        f'  5. {command} start   (or re-run install): it starts only once the state files, the secret and the enrolled',
        f'     companion ({COMPANION_STORE}, written by step 4) verify; never before step 4.',
        f'  Administration: {vdir}/vw-access history --limit 5 (operator {operator}, group {values["human_group"]}; '
        f'the human socket {INSTALL_ROOT}/run/human is the default state root).',
        f'  Agents: an account with primary GID {values["agent_gid"]} creates its key with {vdir}/vw-access setup agent-key '
        f'and uses {INSTALL_ROOT}/run/agent/agent.sock.',
        '  The provider always starts locked: unlock with a fresh password approval in the companion.',
    ]
    return '\n'.join(lines)


# ---- commands --------------------------------------------------------------------------
def new_receipt(reviewed):
    return {'schema': RECEIPT_SCHEMA, 'label': LABEL, 'inputs': reviewed.identity_inputs(), 'status': 'installed',
            'identities_sha256': sha256(reviewed.outputs[plan.IDENTITIES_NAME]),
            'created': {'users': [], 'groups': []}, 'creating': {'users': [], 'groups': []},
            'adopted': {'users': [], 'groups': []}, 'memberships_added': [],
            'versions': {}, 'active_version': None, 'previous_version': None}


def receipt_values(receipt, version):
    return plan.validate_inputs(dict({k: str(v) for k, v in receipt['inputs'].items()}, version=version))


def recorded_plist_hashes(receipt):
    return {record['plist_sha256'] for record in receipt['versions'].values()}


def check_daemon_plist(installer, allowed_hashes):
    """None when absent; the bytes when they hash to one of the recorded plists; refusal otherwise."""
    path = installer.fs(DAEMON_PLIST)
    installer.check_ancestors(DAEMON_PLIST)
    if not os.path.lexists(path):
        return None
    require(path.is_file() and not path.is_symlink(), f'{DAEMON_PLIST} is not a regular file')
    data = installer.read_small(path)
    require(sha256(data) in allowed_hashes, f'{DAEMON_PLIST} exists and was not written by this installer for a recorded version; refusing to replace it')
    return data


def command_install(installer, args):
    reviewed = load_plan(installer, args.plan)
    check_plan_digest(installer, reviewed, args)
    policy = signature_policy(args, required=not installer.dry_run)
    payloads = load_bundle(reviewed, args.bundle)
    require(installer.fs(plan.LAUNCH_DAEMONS).is_dir(), f'{plan.LAUNCH_DAEMONS} does not exist')
    receipt = installer.read_receipt()
    if receipt is not None:
        require(receipt['inputs'] == reviewed.identity_inputs(), 'installed identity (accounts, IDs, groups) differs from this plan; identity changes are not supported')
        active = receipt.get('active_version')
        require(active in (None, reviewed.version), f'version {active} is installed; use upgrade')
    else:
        receipt = new_receipt(reviewed)
    actions = account_actions(installer, reviewed.values, receipt, args.adopt_existing_accounts, installer.read_tombstones())
    identities = installer.fs(IDENTITIES)
    if os.path.lexists(identities):
        require(installer.read_small(identities) == reviewed.outputs[plan.IDENTITIES_NAME], f'{IDENTITIES} exists and differs from the plan')
    plist_bytes = reviewed.outputs[plan.PLIST_NAME]
    existing_plist = check_daemon_plist(installer, {sha256(plist_bytes)})
    for entry in reviewed.directories:
        problems = installer.inspect(entry, 'dir')
        require(not problems, 'existing directory differs from the plan; refusing to change it: ' + '; '.join(problems or []))
    # All checks passed. Mutations follow in a fail-closed order; the receipt records each one first.
    installer.out(f'Installing native provider {reviewed.version} (label {LABEL}) under {installer.root}')
    if policy is None:
        installer.out('  signature policy not chosen: install requires --team-id TEAMID or --allow-development-signature')
    installer.ensure_dir(reviewed.directories[0])
    if not os.path.lexists(installer.fs(RECEIPT)):
        installer.save_receipt(receipt)
    apply_accounts(installer, reviewed.values, actions, receipt)
    for entry in reviewed.directories[1:]:
        if entry['path'] != f'{INSTALL_ROOT}/versions/{reviewed.version}':
            installer.ensure_dir(entry)
    install_version(installer, reviewed, payloads, policy)
    if not os.path.lexists(identities):
        installer.write_file(IDENTITIES, reviewed.outputs[plan.IDENTITIES_NAME], 0, 0, 0o644)
    record = version_record(reviewed, policy)
    if policy is not None and (receipt['versions'].get(reviewed.version) != record or receipt['active_version'] != reviewed.version
                               or receipt['status'] != 'installed'):
        receipt['versions'][reviewed.version] = record
        receipt['active_version'] = reviewed.version
        receipt['status'] = 'installed'
        installer.save_receipt(receipt)
    complete, missing = credential_status(installer, reviewed.files)
    info = installer.service_info()
    if existing_plist is None:
        if not (complete and not args.no_start):
            installer.close_admission()
        installer.write_file(DAEMON_PLIST, plist_bytes, 0, 0, 0o644)
    if complete and not args.no_start:
        if info is None:
            installer.start()
        elif info.get('state') != 'running':
            raise InstallError(f'{SERVICE} is loaded but not running (state {info.get("state", "unknown")}, last exit code '
                               f'{info.get("last exit code", "unknown")}); inspect it, then use stop and start')
        else:
            installer.out(f'  {SERVICE} is running, pid {info.get("pid", "unknown")}')
    else:
        if info is not None:
            installer.out(f'  {SERVICE} is loaded; leaving it running')
        else:
            installer.out(f'  service not started: {"--no-start" if args.no_start else "credentials incomplete"}')
            if existing_plist is not None:
                installer.close_admission()
        for problem in missing:
            installer.out(f'  credential: {problem}')
        installer.out(next_steps(reviewed.values, reviewed.version, actions['operator']))
    return 0


def require_acknowledged(installer, args):
    require(installer.dry_run or args.acknowledge_active_work,
            'stopping the provider closes admission; notify the execution owner of active work (the provider never cancels or '
            'kills consumers), then pass --acknowledge-active-work')


def start_if_ready(installer, files, target, stopped=False):
    complete, missing = credential_status(installer, files)
    if not complete:
        installer.out(f'  service left disabled: credentials incomplete ({"; ".join(missing)})')
        return
    info = None if stopped else installer.service_info()
    if info is not None and info.get('state') == 'running':
        installer.out(f'  {SERVICE} is running, pid {info.get("pid", "unknown")}')
        return
    if info is not None:
        installer.stop()
    installer.start()
    installer.out(f'  provider {target} started; it starts locked: unlock with a fresh password approval')


def switch(installer, receipt, target, plist_bytes, files):
    """Documented order: (verified and recorded already) close admission, bootout, switch, bootstrap locked.

    The `switching` marker stays in the receipt until the service is verified running (or
    deliberately left stopped for incomplete credentials), so a re-run converges on its target.
    """
    current = installer.read_small(installer.fs(DAEMON_PLIST)) if os.path.lexists(installer.fs(DAEMON_PLIST)) else None
    if receipt['active_version'] == target and current == plist_bytes:
        # An interrupted switch already replaced the plist after the bootout: only the start remains.
        start_if_ready(installer, files, target)
    else:
        installer.close_admission()
        installer.stop()
        installer.write_file(DAEMON_PLIST, plist_bytes, 0, 0, 0o644, replace=True)
        if receipt['active_version'] != target:
            receipt['previous_version'], receipt['active_version'] = receipt['active_version'], target
            installer.save_receipt(receipt)
        start_if_ready(installer, files, target, stopped=True)
    finish_switch(installer, receipt)


def finish_switch(installer, receipt):
    """Clear the marker of a switch whose target is active and verified; remember it as the last switch."""
    pending = receipt.get('switching')
    if pending is not None and pending['to'] == receipt['active_version']:
        receipt['last_switch'] = dict(receipt.pop('switching'))
        installer.save_receipt(receipt)


def record_switch(installer, receipt, target, by, source=None):
    """Recorded before the plist changes, so a re-run after a crash recognizes the target plist."""
    pending = receipt.get('switching')
    if pending is not None and pending['to'] == target:
        return  # an interrupted switch to the same target: keep its original record
    receipt['switching'] = {'from': source or receipt['active_version'], 'to': target, 'by': by}
    installer.save_receipt(receipt)


def installed_receipt(installer):
    receipt = installer.read_receipt()
    require(receipt is not None and receipt.get('status') == 'installed' and receipt.get('active_version'),
            'no installation recorded by this installer')
    return receipt


def command_upgrade(installer, args):
    require_acknowledged(installer, args)
    reviewed = load_plan(installer, args.plan)
    check_plan_digest(installer, reviewed, args)
    policy = signature_policy(args, required=not installer.dry_run)
    payloads = load_bundle(reviewed, args.bundle)
    receipt = installed_receipt(installer)
    active = receipt['active_version']
    require(receipt['inputs'] == reviewed.identity_inputs(), 'installed identity differs from this plan; identity changes are not supported')
    current = check_daemon_plist(installer, recorded_plist_hashes(receipt))
    require(current is not None, f'{DAEMON_PLIST} is missing')
    plist_bytes = reviewed.outputs[plan.PLIST_NAME]
    if reviewed.version == active:
        # A re-run after an interrupted upgrade converges instead of refusing.
        require(current == plist_bytes, f'version {active} is active but {DAEMON_PLIST} names another version')
        installer.out(f'Version {active} is already active')
        start_if_ready(installer, reviewed.files, active)
        finish_switch(installer, receipt)
        return 0
    installer.out(f'Upgrading native provider {active} -> {reviewed.version}')
    # 1. Verify a complete new version before closing admission.
    install_version(installer, reviewed, payloads, policy)
    record = version_record(reviewed, policy)
    if receipt['versions'].get(reviewed.version) != record:
        receipt['versions'][reviewed.version] = record
        installer.save_receipt(receipt)
    record_switch(installer, receipt, reviewed.version, 'upgrade')
    switch(installer, receipt, reviewed.version, plist_bytes, reviewed.files)
    return 0


def command_rollback(installer, args):
    receipt = installed_receipt(installer)
    active = receipt['active_version']
    pending = receipt.get('switching')
    resuming = pending is not None and pending.get('by') == 'rollback' and args.to_version in (None, pending['to'])
    interrupted = None
    if resuming:
        # A re-run of an interrupted rollback converges on its target; it never flips back.
        target = pending['to']
        installer.out(f'Resuming the interrupted rollback to {target}')
    else:
        last = receipt.get('last_switch') or {}
        if args.to_version is None and last.get('by') == 'rollback' and last.get('to') == active:
            # A re-run of a completed rollback is a no-op, never a flip back; --to-version switches again.
            installer.out(f'Already rolled back to {active} (from {last.get("from")}); pass --to-version to switch again')
            start_if_ready(installer, layout_files(receipt_values(receipt, active)), active)
            return 0
        interrupted = pending if pending is not None and pending.get('by') == 'upgrade' else None
        if interrupted is not None:
            # An upgrade interrupted between the plist write and the receipt save leaves the receipt
            # naming the old version active while the plist may name the new one: roll back to the
            # version that upgrade left, never to an older previous_version.
            target = args.to_version or interrupted['from']
            installer.out(f'An upgrade {interrupted["from"]} -> {interrupted["to"]} was interrupted; rolling back to {target}')
        else:
            target = args.to_version or receipt.get('previous_version')
        require(target, 'no previous version recorded; pass --to-version')
        require(target != active or interrupted is not None, f'version {target} is already active')
    require(target in receipt['versions'], f'version {target} was not installed by this installer')
    problems = verify_version(installer, target, receipt['versions'][target])
    require(not problems, f'version {target} failed verification; the current version stays active: ' + '; '.join(problems))
    plist_bytes = stored_plist(installer, target)
    require(check_daemon_plist(installer, recorded_plist_hashes(receipt)) is not None, f'{DAEMON_PLIST} is missing')
    require(installer.dry_run or args.confirm_state_compatible,
            f'roll back only to a version that understands the current native profile, account UUIDs and consumed-request schema; '
            f'consumed approvals are never reactivated. Pass --confirm-state-compatible once {target} is confirmed compatible')
    require_acknowledged(installer, args)
    files = layout_files(receipt_values(receipt, target))
    source = pending['from'] if resuming else interrupted['to'] if interrupted is not None else active
    installer.out(f'Rolling back native provider {source} -> {target}')
    record_switch(installer, receipt, target, 'rollback', source=None if resuming else source)
    switch(installer, receipt, target, plist_bytes, files)
    return 0


def command_stop(installer, args):
    require_acknowledged(installer, args)
    installed_receipt(installer)
    installer.out('Stopping the native provider: admission closed (launchctl disable); consumers are never signalled')
    installer.close_admission()
    installer.stop()
    return 0


def command_start(installer, args):
    receipt = installed_receipt(installer)
    active = receipt['active_version']
    problems = verify_version(installer, active, receipt['versions'][active])
    require(not problems, f'active version {active} failed verification: ' + '; '.join(problems))
    require(check_daemon_plist(installer, {receipt['versions'][active]['plist_sha256']}) is not None, f'{DAEMON_PLIST} is missing')
    files = layout_files(receipt_values(receipt, active))
    complete, missing = credential_status(installer, files)
    require(complete, 'credentials incomplete: ' + '; '.join(missing))
    start_if_ready(installer, files, active)
    finish_switch(installer, receipt)
    return 0


def remove_accounts(installer, receipt, retained):
    """Only when nothing provider-owned was retained; tombstones are written before the first deletion."""
    names = receipt['created']['users'] + receipt['created']['groups'] + receipt['creating']['users'] + receipt['creating']['groups']
    if retained:
        retained.append('accounts ' + (', '.join(names) or 'none') + ' (not removed: provider resources were retained, '
                        'so a recreated account could reach them)')
        return
    values = receipt_values(receipt, '0.0.0')
    planned = {user['name']: user for user in plan_users(values)}
    tombstones = installer.read_tombstones()
    recorded = {entry['uuid'] for entry in tombstones}
    new = [{'name': name, 'uid': planned[name]['uid'], 'uuid': planned[name]['uuid']}
           for name in receipt['created']['users'] + receipt['creating']['users'] if name in planned and planned[name]['uuid'] not in recorded]
    if new:
        installer.save_tombstones(tombstones + new)
    for user, group in list(receipt['memberships_added']):
        if user not in receipt['created']['users'] and group not in receipt['created']['groups'] and user in installer.members(group):
            installer.tool('dseditgroup', '-o', 'edit', '-d', user, '-t', 'user', group, mutating=True)
        receipt['memberships_added'].remove([user, group])
        installer.save_receipt(receipt)
    for kind, table, delete in [('users', installer.users, lambda n: installer.tool('dscl', '.', '-delete', f'/Users/{n}', mutating=True)),
                                ('groups', installer.groups, lambda n: installer.tool('dseditgroup', '-o', 'delete', n, mutating=True))]:
        for state in ('created', 'creating'):
            for name in list(receipt[state][kind]):
                if name in table():
                    delete(name)
                else:
                    installer.out(f'  {kind[:-1]} {name} is already absent')
                receipt[state][kind].remove(name)
                installer.save_receipt(receipt)
    for name in receipt['adopted']['users'] + receipt['adopted']['groups']:
        installer.out(f'  kept adopted account {name} (not created by this installer)')


def command_uninstall(installer, args):
    require(not args.remove_accounts or args.purge,
            '--remove-accounts requires --purge: a recreated account with the same UID/UUID must never revive retained enrollment')
    receipt = installer.read_receipt()
    if receipt is None and os.path.lexists(installer.fs(TOMBSTONES)):
        installer.out('Nothing installed by this installer (accounts were removed earlier; tombstones kept)')
        return 0
    require(receipt is not None, 'no installation recorded by this installer')
    require_acknowledged(installer, args)
    receipt_accounts(receipt)
    retained = []
    installer.out('Uninstalling native provider (state, its secrets/ file store and accounts are preserved unless requested)')
    daemon = installer.fs(DAEMON_PLIST)
    # Close admission and stop the service first; consumers are never signalled. Nothing is
    # disabled again once the plist is gone and nothing is loaded.
    if os.path.lexists(daemon) or installer.loaded():
        installer.close_admission()
        installer.stop()
    plist_gone = True
    if os.path.lexists(daemon):
        if daemon.is_file() and not daemon.is_symlink() and sha256(installer.read_small(daemon)) in recorded_plist_hashes(receipt):
            installer.act(f'remove {DAEMON_PLIST}', lambda: os.unlink(daemon))
        else:
            plist_gone = False
            retained.append(f'{DAEMON_PLIST} (not written by this installer)')
    if plist_gone and installer.disabled():
        # The disable override would otherwise persist in launchd's database for this label.
        installer.tool('launchctl', 'enable', SERVICE, mutating=True)
        installer.out(f'  cleared the launchd disable override for {LABEL}')
    for version, record in sorted(receipt['versions'].items()):
        directory = installer.fs(f'{INSTALL_ROOT}/versions/{version}')
        if not os.path.lexists(directory):
            continue
        problems = verify_version(installer, version, record)
        if problems:
            retained.append(f'{INSTALL_ROOT}/versions/{version} (changed: {"; ".join(problems)})')
        else:
            installer.act(f'remove {INSTALL_ROOT}/versions/{version}', lambda d=directory: remove_tree(d))
    identities = installer.fs(IDENTITIES)
    if os.path.lexists(identities):
        if sha256(installer.read_small(identities)) == receipt.get('identities_sha256'):
            installer.act(f'remove {IDENTITIES}', lambda: os.unlink(identities))
        else:
            retained.append(f'{IDENTITIES} (differs from the recorded identity)')
    for relative in ['run/human', 'run/agent', 'run/ssh', 'run', 'versions']:
        remove_empty(installer, f'{INSTALL_ROOT}/{relative}', retained)
    state = installer.fs(f'{INSTALL_ROOT}/state')
    if args.purge and os.path.lexists(state):
        require(state.is_dir() and not state.is_symlink(), f'{INSTALL_ROOT}/state is not a directory')
        installer.act(f'purge {INSTALL_ROOT}/state (provider state, audit history, credential files and the secrets/ store)',
                      lambda: remove_tree(state))
    elif os.path.lexists(state):
        installer.out(f'  preserved {INSTALL_ROOT}/state (provider state, secrets/ file store and credential files; --purge removes it)')
    receipt.update({'status': 'uninstalled', 'versions': {}, 'active_version': None, 'previous_version': None})
    receipt.pop('switching', None)
    receipt.pop('last_switch', None)
    if args.remove_accounts:
        remove_accounts(installer, receipt, retained)
    else:
        names = receipt['created']['users'] + receipt['created']['groups']
        if names:
            installer.out(f'  preserved accounts {", ".join(names)} (pass --purge --remove-accounts to remove them)')
    if args.remove_accounts and not retained:
        # Tombstones stay in the install root so a later install never reuses a removed GeneratedUID.
        installer.act(f'remove {RECEIPT}', lambda: os.unlink(installer.fs(RECEIPT)))
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


def account_report(installer, values, receipt):
    """(lines, problems) for accounts, exact group membership and forbidden memberships."""
    lines, problems = [], []
    users, groups, uuids = installer.users(), installer.groups(), installer.user_uuids()
    operator = next((name for name, uid in users.items() if uid == values['operator_uid']), None)
    if operator is None:
        problems.append(f'operator UID {values["operator_uid"]} has no account')
        operator = OPERATOR
    for user in plan_users(values):
        name = user['name']
        primary = installer.read_attribute('Users', name, 'PrimaryGroupID') if name in users else None
        lines.append(f'  user {name} ({user["role"]}): uid {users.get(name)}, primary gid {" ".join(primary or ["none"])}')
        if (users.get(name), uuids.get(name), primary) != (user['uid'], user['uuid'], [str(user['primary_gid'])]):
            problems.append(f'user {name} is missing or differs from the plan')
    for name, gid, _, members in plan_groups(values, operator):
        current = set(installer.members(name)) if name in groups else set()
        lines.append(f'  group {name} ({groups.get(name)}): members {" ".join(sorted(current)) or "none"}')
        if groups.get(name) != gid:
            problems.append(f'group {name} is missing or has another GID')
        elif current != members:
            problems.append(f'group {name} members {sorted(current)} differ from the plan {sorted(members)}')
    for user, group in required_memberships(values, operator):
        if users.get(user) is not None and groups.get(group) is not None and not installer.is_member(user, group):
            problems.append(f'{user} is not a member of {group}')
    for user, group in forbidden_memberships(values):
        if users.get(user) is not None and groups.get(group) is not None and installer.is_member(user, group):
            problems.append(f'{user} is a member of {group}; a restricted identity must not be')
    return lines, problems


def socket_report(installer):
    lines = []
    for relative in ('run/human', 'run/agent'):
        path = installer.fs(f'{INSTALL_ROOT}/{relative}')
        try:
            names = sorted(os.listdir(path))
        except FileNotFoundError:
            lines.append(f'  {relative}: missing')
            continue
        except PermissionError:
            lines.append(f'  {relative}: unreadable (run status as root or as the operator)')
            continue
        described = []
        for name in names:
            kind = 'socket' if stat.S_ISSOCK(os.lstat(path / name).st_mode) else 'not a socket'
            described.append(f'{name} ({kind})')
        lines.append(f'  {relative}: {", ".join(described) or "no sockets"}')
    return lines


def command_status(installer, args):
    receipt = installer.read_receipt()
    if receipt is None:
        installer.out('not installed by this installer (no receipt)')
        return 1
    receipt_accounts(receipt)
    active = receipt.get('active_version')
    installer.out(f'receipt: status {receipt.get("status")}, active {active}, previous {receipt.get("previous_version")}, '
                  f'versions {", ".join(sorted(receipt.get("versions", {}))) or "none"}')
    installer.out(f'created accounts: {", ".join(receipt["created"]["users"] + receipt["created"]["groups"]) or "none"}; '
                  f'adopted: {", ".join(receipt["adopted"]["users"] + receipt["adopted"]["groups"]) or "none"}')
    if receipt.get('status') != 'installed' or not active:
        return 1
    values = receipt_values(receipt, active)
    document = layout(values)
    problems = []
    pending = receipt.get('switching')
    if pending is not None:
        problems.append(f'{pending.get("by", "upgrade")} switch to {pending["to"]} is pending (from {pending["from"]}); '
                        'the service was not verified running: re-run the same command')
    lines, account_problems = account_report(installer, values, receipt)
    installer.out('accounts:')
    for line in lines:
        installer.out(line)
    problems.extend(account_problems)
    for entry in document['directories']:
        try:
            found = installer.inspect(entry, 'dir')
        except (OSError, InstallError) as error:
            found = [f'{entry["path"]} unreadable: {error}']
        problems.extend([f'{entry["path"]} is missing'] if found is None else found)
    for version, record in sorted(receipt['versions'].items()):
        found = verify_version(installer, version, record)
        problems.extend(found)
        installer.out(f'version {version}: {"verified" if not found else "FAILED"}')
    files = {e['path']: e for e in document['files']}
    for destination, expected in [(IDENTITIES, receipt.get('identities_sha256')),
                                  (DAEMON_PLIST, receipt['versions'].get(active, {}).get('plist_sha256'))]:
        found = installer.inspect(files[destination], 'file')
        if found is None:
            problems.append(f'{destination} is missing')
            continue
        problems.extend(found)
        if sha256(installer.read_small(installer.fs(destination))) != expected:
            problems.append(f'{destination} differs from the recorded copy for the active version {active}')
    complete, missing = credential_status(installer, files)
    installer.out(f'credentials: {"present" if complete else "incomplete"}')
    for item in missing:
        installer.out(f'  {item}')
    installer.out('sockets:')
    for line in socket_report(installer):
        installer.out(line)
    info, disabled = installer.service_info(), installer.disabled()
    if info is None:
        installer.out(f'service {SERVICE}: not loaded, {"disabled" if disabled else "enabled"}')
    else:
        installer.out(f'service {SERVICE}: loaded, {"disabled" if disabled else "enabled"}, state {info.get("state", "unknown")}, '
                      f'pid {info.get("pid", "none")}, last exit code {info.get("last exit code", "unknown")}')
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
            sub.add_argument('--expect-plan-sha256', metavar='HEX', help='digest of the reviewed plan.json (required unless --dry-run)')
            sub.add_argument('--team-id', metavar='TEAMID', help='require an Apple-issued signature of this team (Developer ID)')
            sub.add_argument('--allow-development-signature', action='store_true', help='accept an ad-hoc development signature')
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
    sub = add('stop', 'close admission and boot the service out (for offline companion enrollment)')
    sub.add_argument('--acknowledge-active-work', action='store_true')
    add('start', 'start the active version once its credentials verify')
    sub = add('uninstall', 'remove the service and installer-owned files')
    sub.add_argument('--purge', action='store_true', help='also remove the provider state directory (credentials, audit history)')
    sub.add_argument('--remove-accounts', action='store_true', help='with --purge: remove accounts and groups this installer created')
    sub.add_argument('--acknowledge-active-work', action='store_true')
    add('status', 'verify the installation (read-only)', mutating=False)
    return top


COMMANDS = {'plan': command_install, 'install': command_install, 'upgrade': command_upgrade, 'rollback': command_rollback,
            'stop': command_stop, 'start': command_start, 'uninstall': command_uninstall, 'status': command_status}


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
        if effective_uid() == 0:
            # Any run as root executes this code as root, a dry run or status included.
            check_code_trust(code_paths())
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
    except OSError as error:
        print(f'macos-provider-install: {error}', file=sys.stderr)
        return EXIT_REFUSED
    if dry_run:
        out(f'Dry run: {installer.changes} action(s) listed; nothing was changed.')
    elif args.command != 'status' and installer.changes == 0:
        out('No changes: the installation already matches.')
    return code


if __name__ == '__main__':
    sys.exit(main())
