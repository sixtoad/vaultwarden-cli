#!/usr/bin/env python3
"""Resolve the native macOS provider templates into a reviewable installer plan.

This is review material only. It reads the two templates under
packaging/macos/native/, validates every explicit input, and writes three files
into a caller-chosen output directory:

  com.cantolla.vaultwarden-accessd.plist   resolved LaunchDaemon definition
  native-identities.json                   resolved provider identity record
  plan.json                                destinations, owners, modes, hashes

It installs nothing: it starts no process, changes no account or service and
writes nowhere except the output directory, which must be new or empty. The
destinations in plan.json are what a separately reviewed, manual installation
would use (docs/implementation/issue-49-native-provider.md).
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import sys

sys.dont_write_bytecode = True

REPO = Path(__file__).resolve().parents[1]
TEMPLATES = REPO / 'packaging/macos/native'
PLIST_TEMPLATE = 'com.cantolla.vaultwarden-accessd.plist.in'
IDENTITIES_TEMPLATE = 'native-identities.json.in'
PLIST_NAME = 'com.cantolla.vaultwarden-accessd.plist'
IDENTITIES_NAME = 'native-identities.json'
PLAN_NAME = 'plan.json'
LABEL = 'com.cantolla.vaultwarden-accessd'
INSTALL_ROOT = '/Library/VaultwardenAccess'
BUNDLE_HELPERS = 'Contents/Helpers'
# Rust reads the identity record with a 4096-byte cap (src/adapters/native/identity.rs).
IDENTITIES_MAX = 4096

PLACEHOLDER = re.compile(r'@[A-Za-z0-9_]+@')
VERSION = re.compile(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?')
NAME = re.compile(r'[a-z_][a-z0-9_-]{0,31}')
UUID = re.compile(r'[0-9a-f]{32}')
INTEGER = re.compile(r'[1-9][0-9]{0,9}')
# 0 is root/wheel; 4294967295 is (uid_t)-1. Both are refused, as is any value
# that does not fit an unsigned 32-bit id.
ID_MAX = 4294967294
RESERVED_NAMES = {'root', 'wheel'}
# Never resolve straight into a live system location.
FORBIDDEN_OUTPUT_ROOTS = ('/Library', '/System', '/private/var/root', '/usr', '/bin', '/sbin', '/etc', '/private/etc')


class PlanError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise PlanError(message)


def parse_id(label, value):
    require(isinstance(value, str) and INTEGER.fullmatch(value) is not None, f'{label} must be a decimal integer without sign or leading zeros')
    number = int(value)
    require(1 <= number <= ID_MAX, f'{label} must be between 1 and {ID_MAX}')
    return number


def parse_uuid(label, value):
    require(isinstance(value, str) and UUID.fullmatch(value) is not None, f'{label} must be 32 lowercase hexadecimal digits without dashes')
    require(value != '0' * 32, f'{label} must not be the null UUID')
    return value


def parse_name(label, value):
    require(isinstance(value, str) and NAME.fullmatch(value) is not None, f'{label} must be a short account/group name ([a-z_][a-z0-9_-]{{0,31}})')
    require(value not in RESERVED_NAMES, f'{label} must not be {value}')
    return value


def parse_version(value):
    require(isinstance(value, str) and VERSION.fullmatch(value) is not None, 'version must be MAJOR.MINOR.PATCH with an optional alphanumeric pre-release')
    return value


def validate_inputs(raw):
    """Return typed inputs or raise PlanError. Mirrors the provider's own checks."""
    expected = {'version', 'provider_account', 'provider_group', 'provider_uid', 'provider_uuid',
                'operator_uid', 'operator_uuid', 'human_gid', 'agent_gid'}
    require(set(raw) == expected, 'inputs must be exactly: ' + ', '.join(sorted(expected)))
    values = {
        'version': parse_version(raw['version']),
        'provider_account': parse_name('provider account', raw['provider_account']),
        'provider_group': parse_name('provider group', raw['provider_group']),
        'provider_uid': parse_id('provider UID', raw['provider_uid']),
        'provider_uuid': parse_uuid('provider UUID', raw['provider_uuid']),
        'operator_uid': parse_id('operator UID', raw['operator_uid']),
        'operator_uuid': parse_uuid('operator UUID', raw['operator_uuid']),
        'human_gid': parse_id('human GID', raw['human_gid']),
        'agent_gid': parse_id('agent GID', raw['agent_gid']),
    }
    require(values['provider_uid'] != values['operator_uid'], 'provider and operator UIDs must differ')
    require(values['provider_uuid'] != values['operator_uuid'], 'provider and operator UUIDs must differ')
    require(values['human_gid'] != values['agent_gid'], 'human and agent GIDs must differ')
    return values


def payload_destination(version):
    return f'{INSTALL_ROOT}/versions/{version}/vaultwarden-accessd'


def substitute(text, replacements):
    """Replace known tokens; any placeholder left afterwards is an error."""
    for token, value in replacements.items():
        text = text.replace(token, value)
    left = sorted(set(PLACEHOLDER.findall(text)))
    require(not left, 'unresolved template placeholder(s): ' + ', '.join(left))
    return text


def resolve_plist(template, values):
    text = substitute(template, {
        '@VERSION@': values['version'],
        '@AGENT_GID@': str(values['agent_gid']),
        '@PROVIDER_ACCOUNT@': values['provider_account'],
        '@PROVIDER_GROUP@': values['provider_group'],
    })
    try:
        parsed = plistlib.loads(text.encode())
    except Exception as error:  # plistlib raises several parser-specific types.
        raise PlanError(f'resolved plist does not parse: {error}') from None
    check_plist(parsed, values)
    return text.encode()


def check_plist(parsed, values):
    """Security-critical LaunchDaemon keys must survive resolution unchanged."""
    arguments = parsed.get('ProgramArguments')
    require(isinstance(arguments, list) and arguments, 'plist ProgramArguments missing')
    require(arguments[0] == payload_destination(values['version']), 'plist program is not the versioned provider payload')
    require('--agent-socket-gid' in arguments and arguments[arguments.index('--agent-socket-gid') + 1:][:1] == [str(values['agent_gid'])], 'plist agent socket GID mismatch')
    expected = {
        'Label': LABEL,
        'UserName': values['provider_account'],
        'GroupName': values['provider_group'],
        'AbandonProcessGroup': True,
        'SoftResourceLimits': {'Core': 0},
        'HardResourceLimits': {'Core': 0},
        'StandardOutPath': '/dev/null',
        'StandardErrorPath': '/dev/null',
        'InitGroups': True,
    }
    for key, value in expected.items():
        require(parsed.get(key) == value and type(parsed.get(key)) is type(value), f'plist {key} must be {value!r}')
    require('StandardInPath' not in parsed and 'EnvironmentVariables' not in parsed, 'plist must not add stdin or environment')
    require(parsed.get('UserName') != 'root', 'provider must not run as root')


def resolve_identities(template, values):
    try:
        document = json.loads(template)
    except json.JSONDecodeError as error:
        raise PlanError(f'identity template does not parse: {error}') from None
    typed = {
        '@PROVIDER_UID_AS_INTEGER@': values['provider_uid'],
        '@PROVIDER_GENERATED_UUID_LOWERCASE_HEX_WITHOUT_DASHES@': values['provider_uuid'],
        '@OPERATOR_UID_AS_INTEGER@': values['operator_uid'],
        '@OPERATOR_GENERATED_UUID_LOWERCASE_HEX_WITHOUT_DASHES@': values['operator_uuid'],
        '@HUMAN_GID_AS_INTEGER@': values['human_gid'],
        '@AGENT_GID_AS_INTEGER@': values['agent_gid'],
    }
    require(isinstance(document, dict), 'identity template must be an object')
    resolved = {}
    for key, value in document.items():
        resolved[key] = typed[value] if isinstance(value, str) and value in typed else value
    text = json.dumps(resolved, indent=2, ensure_ascii=True) + '\n'
    left = sorted(set(PLACEHOLDER.findall(text)))
    require(not left, 'unresolved template placeholder(s): ' + ', '.join(left))
    # The provider deserializes with deny_unknown_fields; keep the exact shape.
    integers = ['provider_uid', 'operator_uid', 'human_gid', 'agent_gid']
    strings = ['provider_uuid', 'operator_uuid', 'human_socket_dir', 'ssh_runtime_dir']
    require(sorted(resolved) == sorted(integers + strings), 'identity record has unexpected fields')
    require(all(type(resolved[k]) is int for k in integers), 'identity UID/GID fields must be JSON integers')
    require(all(isinstance(resolved[k], str) for k in strings), 'identity UUID/path fields must be strings')
    require(all(resolved[k].startswith(INSTALL_ROOT + '/') for k in ['human_socket_dir', 'ssh_runtime_dir']), 'identity runtime paths must stay under ' + INSTALL_ROOT)
    data = text.encode()
    require(len(data) <= IDENTITIES_MAX, 'identity record exceeds the provider size limit')
    return data


def plan_document(values, outputs):
    version = values['version']
    return {
        'schema': 1,
        'installs': False,
        'note': 'Review material only. Nothing has been installed. Development signing only; Apple Silicon (arm64) only; Intel and Rosetta are unsupported.',
        'version': version,
        'inputs': {k: values[k] for k in sorted(values)},
        'files': [
            {'source': PLIST_NAME, 'sha256': hashlib.sha256(outputs[PLIST_NAME]).hexdigest(),
             'destination': f'/Library/LaunchDaemons/{PLIST_NAME}', 'owner': 'root', 'group': 'wheel', 'mode': '0644'},
            {'source': IDENTITIES_NAME, 'sha256': hashlib.sha256(outputs[IDENTITIES_NAME]).hexdigest(),
             'destination': f'{INSTALL_ROOT}/{IDENTITIES_NAME}', 'owner': 'root', 'group': 'wheel', 'mode': '0644'},
            {'source': f'bundle:{BUNDLE_HELPERS}/vaultwarden-accessd', 'destination': payload_destination(version),
             'owner': 'root', 'group': 'wheel', 'mode': '0555', 'version_from': 'bundle.json cli_version'},
            {'source': f'bundle:{BUNDLE_HELPERS}/vw-access', 'destination': f'{INSTALL_ROOT}/versions/{version}/vw-access',
             'owner': 'root', 'group': 'wheel', 'mode': '0555', 'version_from': 'bundle.json cli_version'},
        ],
    }


def build(values, templates=TEMPLATES):
    """Pure resolution: returns {file name: bytes}. Writes nothing."""
    outputs = {
        PLIST_NAME: resolve_plist((templates / PLIST_TEMPLATE).read_text(), values),
        IDENTITIES_NAME: resolve_identities((templates / IDENTITIES_TEMPLATE).read_text(), values),
    }
    outputs[PLAN_NAME] = (json.dumps(plan_document(values, outputs), indent=2, ensure_ascii=True) + '\n').encode()
    return outputs


def check_bundle(bundle, version):
    """Optional cross-check that a built macOS arm64 bundle ships this version."""
    manifest_path = bundle / 'Contents/Resources/bundle.json'
    try:
        manifest = json.loads(manifest_path.read_text())
    except (OSError, ValueError):
        raise PlanError(f'cannot read bundle manifest: {manifest_path}') from None
    require(manifest.get('platform') == 'macos' and manifest.get('architecture') == 'aarch64', 'bundle is not a macOS arm64 bundle')
    require(manifest.get('roles', {}).get('protected_provider') is True, 'bundle does not ship the protected provider')
    require(manifest.get('cli_version') == version, f"bundle provider version {manifest.get('cli_version')!r} differs from {version!r}")
    payloads = {entry.get('path'): entry for entry in manifest.get('payloads', [])}
    for name in ['vaultwarden-accessd', 'vw-access']:
        entry = payloads.get(f'{BUNDLE_HELPERS}/{name}')
        require(entry is not None and entry.get('executable') is True, f'bundle lacks {BUNDLE_HELPERS}/{name}')
        path = bundle / BUNDLE_HELPERS / name
        require(path.is_file() and not path.is_symlink(), f'bundle payload missing: {path}')
        require(hashlib.sha256(path.read_bytes()).hexdigest() == entry.get('sha256'), f'bundle payload damaged: {path}')
    return {name: payloads[f'{BUNDLE_HELPERS}/{name}']['sha256'] for name in ['vaultwarden-accessd', 'vw-access']}


def attach_bundle_hashes(outputs, hashes):
    plan = json.loads(outputs[PLAN_NAME])
    for entry in plan['files']:
        for name, digest in hashes.items():
            if entry['source'] == f'bundle:{BUNDLE_HELPERS}/{name}':
                entry['sha256'] = digest
    outputs[PLAN_NAME] = (json.dumps(plan, indent=2, ensure_ascii=True) + '\n').encode()


def prepare_output(output):
    """The output directory is new or empty, and never a system location."""
    absolute = Path(os.path.abspath(output))
    resolved = absolute.resolve()
    # Also compare the path as given in POSIX form: on a Windows host
    # '/Library' resolves to a drive path that no macOS root would match.
    candidates = [PurePosixPath(p.as_posix()) for p in (Path(output), absolute, resolved)]
    for candidate in candidates:
        for root in FORBIDDEN_OUTPUT_ROOTS:
            require(not candidate.is_relative_to(root), f'refusing to write into system location {candidate}')
    if absolute.is_symlink():
        raise PlanError('output directory must not be a symbolic link')
    if absolute.exists():
        require(absolute.is_dir(), 'output path exists and is not a directory')
        require(not any(absolute.iterdir()), 'output directory must be empty')
    else:
        require(absolute.parent.is_dir(), 'output directory parent does not exist')
        absolute.mkdir(mode=0o755)
    return absolute


def write(output, outputs):
    directory = prepare_output(output)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0)
    for name in sorted(outputs):
        descriptor = os.open(directory / name, flags, 0o644)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(outputs[name])
    return directory


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--output', required=True, type=Path, help='new or empty directory that receives the plan')
    parser.add_argument('--version', required=True, help='provider version; must equal the bundle cli_version')
    parser.add_argument('--provider-account', required=True)
    parser.add_argument('--provider-group', required=True)
    parser.add_argument('--provider-uid', required=True)
    parser.add_argument('--provider-uuid', required=True, help='GeneratedUID, 32 lowercase hex digits, no dashes')
    parser.add_argument('--operator-uid', required=True)
    parser.add_argument('--operator-uuid', required=True, help='GeneratedUID, 32 lowercase hex digits, no dashes')
    parser.add_argument('--human-gid', required=True)
    parser.add_argument('--agent-gid', required=True)
    parser.add_argument('--bundle', type=Path, help='optional built macOS arm64 .app to cross-check version and hashes')
    args = parser.parse_args(argv)
    raw = {key: getattr(args, key) for key in ['version', 'provider_account', 'provider_group', 'provider_uid', 'provider_uuid',
                                               'operator_uid', 'operator_uuid', 'human_gid', 'agent_gid']}
    try:
        values = validate_inputs(raw)
        outputs = build(values)
        if args.bundle is not None:
            attach_bundle_hashes(outputs, check_bundle(args.bundle, values['version']))
        directory = write(args.output, outputs)
    except PlanError as error:
        print(f'macos-provider-plan: {error}', file=sys.stderr)
        return 2
    print(f'Installer plan written to {directory} (review material; nothing installed).')
    return 0


if __name__ == '__main__':
    sys.exit(main())
