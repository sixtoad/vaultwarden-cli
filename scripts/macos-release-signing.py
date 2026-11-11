#!/usr/bin/env python3
"""Developer ID signing, verification and notarization of the arm64 macOS desktop bundle (#62).

`scripts/desktop-bundle.py` calls this module while it builds the bundle, so every
signature exists before `bundle.json` hashes the payloads. Configuration comes only
from the environment: CI secrets (`scripts/ci-macos-signing.sh`) or the publisher's
own Keychain (`scripts/release-macos-desktop-bundle.sh`). Nothing secret is read
from or written into the repository.

Signing (all unset: the development, ad hoc build):
  MACOS_SIGNING_IDENTITY      "Developer ID Application: NAME (TEAMID)" or its SHA-1
  MACOS_PROVISIONING_PROFILE  Developer ID profile of the app (keychain-access-groups)
  MACOS_TEAM_ID               expected team, default the release team 9884BZY594
  MACOS_SIGNING_KEYCHAIN      optional keychain file holding the identity (CI)
Notarization (optional, one of):
  MACOS_NOTARY_KEYCHAIN_PROFILE  name stored by `xcrun notarytool store-credentials`
  MACOS_NOTARY_KEY_PATH, MACOS_NOTARY_KEY_ID, MACOS_NOTARY_ISSUER_ID
                                 App Store Connect API key (.p8 file, key id, issuer)

Commands (no secret value is ever printed):
  status            what the environment configures
  verify APP        Developer ID verification of a built bundle
  notarize APP      notarize, staple and assess a signed bundle
"""
import argparse
import datetime
from dataclasses import dataclass
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True

# The release publisher. The native provider pins the same team and clause in
# src/adapters/native/image.rs (RELEASE_TEAM_ID, DEVELOPER_ID).
RELEASE_TEAM_ID = '9884BZY594'
DEVELOPER_ID = ('anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and '
                'certificate leaf[field.1.2.840.113635.100.6.1.13] exists')
TEAM = re.compile(r'[A-Z0-9]{10}')
SHA1 = re.compile(r'[0-9A-F]{40}')
APP_EXECUTABLE = 'Contents/MacOS/companion_slice'
HELPERS = 'Contents/Helpers'
PROFILE_NAME = 'Contents/embedded.provisionprofile'
# Entitlements that a provisioning profile must grant; everything else is a
# sandbox capability the app declares in companion/macos/Runner/Release.entitlements.
RESTRICTED = ('com.apple.application-identifier', 'com.apple.developer.team-identifier', 'keychain-access-groups')
# Never present in any signed component (the provider's image policy rejects the same).
FORBIDDEN = (
    'com.apple.security.get-task-allow',
    'com.apple.security.cs.disable-library-validation',
    'com.apple.security.cs.allow-dyld-environment-variables',
    'com.apple.security.cs.allow-unsigned-executable-memory',
    'com.apple.security.cs.allow-jit',
    'com.apple.security.cs.disable-executable-page-protection',
)
MACHO = {b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe', b'\xca\xfe\xba\xbe', b'\xca\xfe\xba\xbf'}
CODESIGN = '/usr/bin/codesign'


class SigningError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise SigningError(message)


@dataclass(frozen=True)
class Signing:
    identity: str
    team: str
    profile: Path
    keychain: Path | None = None


@dataclass(frozen=True)
class Notary:
    keychain_profile: str | None = None
    key_path: Path | None = None
    key_id: str | None = None
    issuer: str | None = None

    def arguments(self):
        if self.keychain_profile:
            return ['--keychain-profile', self.keychain_profile]
        return ['--key', str(self.key_path), '--key-id', self.key_id, '--issuer', self.issuer]

    def describe(self):
        return 'keychain profile' if self.keychain_profile else 'App Store Connect API key'


def signing_from_env(env):
    """The configured Developer ID signing, or None for the development build."""
    identity = env.get('MACOS_SIGNING_IDENTITY', '').strip()
    profile = env.get('MACOS_PROVISIONING_PROFILE', '').strip()
    if not identity:
        require(not profile, 'MACOS_PROVISIONING_PROFILE is set without MACOS_SIGNING_IDENTITY')
        return None
    team = env.get('MACOS_TEAM_ID', '').strip() or RELEASE_TEAM_ID
    require(TEAM.fullmatch(team) is not None, 'MACOS_TEAM_ID must be 10 uppercase letters or digits')
    if not SHA1.fullmatch(identity):
        require(identity.startswith('Developer ID Application: ') and identity.endswith(f'({team})'),
                f'MACOS_SIGNING_IDENTITY must be a "Developer ID Application: ... ({team})" identity or its SHA-1')
    require(profile, 'MACOS_PROVISIONING_PROFILE is required for Developer ID signing (the app needs keychain-access-groups)')
    keychain = env.get('MACOS_SIGNING_KEYCHAIN', '').strip()
    return Signing(identity, team, Path(profile), Path(keychain) if keychain else None)


def notary_from_env(env):
    """The configured notary credentials, or None (signed but not notarized)."""
    profile = env.get('MACOS_NOTARY_KEYCHAIN_PROFILE', '').strip()
    key = [env.get(name, '').strip() for name in ('MACOS_NOTARY_KEY_PATH', 'MACOS_NOTARY_KEY_ID', 'MACOS_NOTARY_ISSUER_ID')]
    if profile:
        require(not any(key), 'configure either MACOS_NOTARY_KEYCHAIN_PROFILE or the API key, not both')
        return Notary(keychain_profile=profile)
    if not any(key):
        return None
    require(all(key), 'the notary API key needs MACOS_NOTARY_KEY_PATH, MACOS_NOTARY_KEY_ID and MACOS_NOTARY_ISSUER_ID')
    require(Path(key[0]).is_file(), 'MACOS_NOTARY_KEY_PATH does not name a file')
    return Notary(key_path=Path(key[0]), key_id=key[1], issuer=key[2])


def designated_requirement(team):
    """Developer ID Application of one team; the provider installer's --team-id requirement."""
    require(TEAM.fullmatch(team) is not None, 'team identifier must be 10 uppercase letters or digits')
    return f'{DEVELOPER_ID} and certificate leaf[subject.OU] = "{team}"'


def read_profile(path, run=subprocess.run):
    result = run(['/usr/bin/security', 'cms', '-D', '-i', str(path)], capture_output=True, check=False)
    require(result.returncode == 0, f'cannot decode provisioning profile {path}')
    try:
        return plistlib.loads(result.stdout)
    except Exception:
        raise SigningError(f'provisioning profile {path} is not a property list') from None


def check_profile(profile, team, bundle_id, now=None):
    """A Developer ID macOS profile of this team and app; returns its entitlements."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    require(profile.get('Platform') == ['OSX'], 'provisioning profile is not a macOS profile')
    require(profile.get('TeamIdentifier') == [team], f'provisioning profile is not for team {team}')
    # Developer ID profiles provision every device; development profiles list devices.
    require(profile.get('ProvisionsAllDevices') is True and 'ProvisionedDevices' not in profile,
            'provisioning profile is not a Developer ID profile (it lists devices)')
    expires = profile.get('ExpirationDate')
    require(isinstance(expires, datetime.datetime), 'provisioning profile has no expiration date')
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=datetime.timezone.utc)
    require(expires > now, 'provisioning profile has expired')
    entitlements = profile.get('Entitlements')
    require(isinstance(entitlements, dict), 'provisioning profile has no entitlements')
    require(entitlements.get('com.apple.application-identifier') == f'{team}.{bundle_id}',
            f'provisioning profile is for {entitlements.get("com.apple.application-identifier")}, not {team}.{bundle_id}')
    require(entitlements.get('com.apple.developer.team-identifier') == team, 'provisioning profile team entitlement differs')
    for name in ('com.apple.security.get-task-allow', 'get-task-allow'):
        require(entitlements.get(name) is not True, 'provisioning profile grants get-task-allow (a development profile)')
    return entitlements


def granted(value, allowed):
    """Profile wildcard rule: `TEAM.*` admits any group of that team."""
    return value == allowed or (allowed.endswith('.*') and value.startswith(allowed[:-1]))


def app_entitlements(declared, team, bundle_id, profile_entitlements):
    """Release.entitlements plus the identity the profile grants: the minimum the app needs."""
    require(not set(declared) & set(RESTRICTED), 'Release.entitlements must not declare restricted entitlements')
    require(not set(declared) & set(FORBIDDEN), 'Release.entitlements declares a forbidden entitlement')
    group = f'{team}.{bundle_id}'
    allowed = profile_entitlements.get('keychain-access-groups') or []
    require(any(granted(group, pattern) for pattern in allowed), f'provisioning profile does not grant keychain group {group}')
    return {**declared, 'com.apple.application-identifier': f'{team}.{bundle_id}',
            'com.apple.developer.team-identifier': team, 'keychain-access-groups': [group]}


def is_macho(path):
    if path.is_symlink() or not path.is_file():
        return False
    with path.open('rb') as stream:
        return stream.read(4) in MACHO


def walk(root):
    """Every regular file and directory below root, never through a symbolic link."""
    for directory, names, files in os.walk(root, followlinks=False):
        base = Path(directory)
        for name in names:
            if not (base / name).is_symlink():
                yield base / name
        for name in files:
            yield base / name


def framework_binary(framework, path):
    """The framework's own binary, sealed by signing the framework itself."""
    relative = path.relative_to(framework).parts
    return relative[-1] == framework.stem and (len(relative) == 1 or (len(relative) == 3 and relative[0] == 'Versions'))


def signing_order(root):
    """Nested code inside out: loose Mach-O files, then frameworks (deepest first).

    The app itself is signed last, by `sign_app`.
    """
    main = root / APP_EXECUTABLE
    paths = sorted(walk(root))
    frameworks = sorted((p for p in paths if p.suffix == '.framework' and p.is_dir()), key=lambda p: (-len(p.parts), str(p)))
    loose = []
    for path in paths:
        if path == main or not is_macho(path):
            continue
        owner = next((f for f in frameworks if path.is_relative_to(f)), None)
        if owner is not None and framework_binary(owner, path):
            continue
        loose.append(path)
    return loose + frameworks


def codesign_arguments(signing):
    arguments = [CODESIGN, '--force', '--sign', signing.identity, '--options', 'runtime', '--timestamp']
    if signing.keychain:
        arguments += ['--keychain', str(signing.keychain)]
    return arguments


def sign_nested(root, signing, run=subprocess.run):
    """Sign helpers, libraries and frameworks with a hardened runtime and no entitlements."""
    signed = []
    for path in signing_order(root):
        arguments = codesign_arguments(signing)
        if path.parent == root / HELPERS:
            arguments += ['--identifier', f'dev.vaultwarden.{path.name}']
        run(arguments + [str(path)], check=True)
        signed.append(path)
    return signed


def embed_profile(root, signing, bundle_id, run=subprocess.run):
    """Copy the checked profile into the app before the manifest hashes payloads."""
    entitlements = check_profile(read_profile(signing.profile, run), signing.team, bundle_id)
    shutil.copyfile(signing.profile, root / PROFILE_NAME)
    (root / PROFILE_NAME).chmod(0o644)
    return entitlements


def bundle_identifier(root):
    with (root / 'Contents/Info.plist').open('rb') as stream:
        value = plistlib.load(stream).get('CFBundleIdentifier')
    require(isinstance(value, str) and value, 'app Info.plist has no CFBundleIdentifier')
    return value


def sign_app(root, signing, entitlements, run=subprocess.run):
    with tempfile.TemporaryDirectory(prefix='app-entitlements-') as temporary:
        path = Path(temporary) / 'app.entitlements'
        path.write_bytes(plistlib.dumps(entitlements))
        run(codesign_arguments(signing) + ['--entitlements', str(path), str(root)], check=True)


def entitlements_of(path, run=subprocess.run):
    result = run([CODESIGN, '-d', '--entitlements', ':-', str(path)], capture_output=True, check=False)
    require(result.returncode == 0, f'{path}: codesign -d --entitlements failed')
    return plistlib.loads(result.stdout) if result.stdout.strip() else {}


def details(path, run=subprocess.run):
    result = run([CODESIGN, '-d', '--verbose=2', str(path)], capture_output=True, text=True, check=False)
    require(result.returncode == 0, f'{path}: codesign -d failed')
    return result.stdout + result.stderr


def verify(root, team, expected_entitlements=None, run=subprocess.run):
    """Developer ID of `team`, hardened runtime, minimum entitlements, for every component."""
    requirement = '=' + designated_requirement(team)
    result = run([CODESIGN, '--verify', '--deep', '--strict', '-R', requirement, str(root)], capture_output=True, text=True, check=False)
    require(result.returncode == 0, f'{root} fails Developer ID verification for team {team}: {result.stderr.strip()[:300]}')
    for path in [*signing_order(root), root]:
        result = run([CODESIGN, '--verify', '--strict', '-R', requirement, str(path)], capture_output=True, text=True, check=False)
        require(result.returncode == 0, f'{path} is not signed by Developer ID team {team}')
        info = details(path, run)
        require(f'TeamIdentifier={team}' in info.splitlines(), f'{path} has another team identifier')
        require(re.search(r'flags=0x[0-9a-f]*\([^)]*runtime', info) is not None, f'{path} has no hardened runtime')
        require('Timestamp=' in info, f'{path} has no secure timestamp')
        entitlements = entitlements_of(path, run)
        require(not set(entitlements) & set(FORBIDDEN), f'{path} has a forbidden entitlement')
        if path != root:
            require(not entitlements, f'{path} must carry no entitlements')
    if expected_entitlements is not None:
        actual = entitlements_of(root, run)
        require(actual == expected_entitlements, f'app entitlements differ from the minimum set: {sorted(actual)}')
    profile = root / PROFILE_NAME
    require(profile.is_file() and not profile.is_symlink(), 'app has no embedded provisioning profile')


def notarize(root, notary, work, run=subprocess.run):
    """Submit the signed app, wait, staple the ticket and assess it with Gatekeeper."""
    work.mkdir(parents=True, exist_ok=True)
    archive = work / f'{root.stem}-notarization.zip'
    run(['/usr/bin/ditto', '-c', '-k', '--keepParent', str(root), str(archive)], check=True)
    print(f'notarizing {root.name} with the {notary.describe()} (waits for Apple)')
    try:
        result = run(['/usr/bin/xcrun', 'notarytool', 'submit', str(archive), *notary.arguments(), '--wait', '--timeout', '30m',
                      '--output-format', 'json'], capture_output=True, text=True, check=False)
    finally:
        archive.unlink(missing_ok=True)
    try:
        submission = json.loads(result.stdout)
    except json.JSONDecodeError:
        raise SigningError(f'notarytool submit failed: {result.stderr.strip()[:500]}') from None
    identifier, status = submission.get('id'), submission.get('status')
    (work / 'notarization-submission.json').write_text(json.dumps(submission, indent=2) + '\n')
    if status != 'Accepted':
        if identifier:
            log = run(['/usr/bin/xcrun', 'notarytool', 'log', identifier, *notary.arguments()], capture_output=True, text=True, check=False)
            (work / 'notarization-log.json').write_text(log.stdout)
            print(log.stdout, file=sys.stderr)
        raise SigningError(f'notarization {identifier or "(no id)"} ended with status {status!r}')
    run(['/usr/bin/xcrun', 'stapler', 'staple', str(root)], check=True)
    run(['/usr/bin/xcrun', 'stapler', 'validate', str(root)], check=True)
    assessment = run(['/usr/sbin/spctl', '--assess', '--type', 'execute', '--verbose=2', str(root)], capture_output=True, text=True, check=False)
    output = assessment.stdout + assessment.stderr
    require(assessment.returncode == 0 and 'source=Notarized Developer ID' in output, f'Gatekeeper rejects the stapled app: {output.strip()[:300]}')
    print(f'notarized and stapled: {identifier}')
    return identifier


def describe(env):
    signing, notary = signing_from_env(env), notary_from_env(env)
    if signing is None:
        return 'development build: no Developer ID signing configured (MACOS_SIGNING_IDENTITY unset)'
    lines = [f'Developer ID signing for team {signing.team} with profile {signing.profile.name}' +
             (' from a dedicated keychain' if signing.keychain else '')]
    lines.append(f'notarization with the {notary.describe()}' if notary else 'notarization NOT configured: the bundle will be signed but not notarized')
    return '\n'.join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('status')
    for name in ('verify', 'notarize'):
        sub.add_parser(name).add_argument('app', type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == 'status':
            print(describe(os.environ))
        elif args.command == 'verify':
            signing = signing_from_env(os.environ)
            verify(args.app.resolve(), signing.team if signing else os.environ.get('MACOS_TEAM_ID') or RELEASE_TEAM_ID)
            print(f'{args.app}: Developer ID verified')
        else:
            notary = notary_from_env(os.environ)
            require(notary is not None, 'no notary credentials configured')
            with tempfile.TemporaryDirectory(prefix='notarize-') as temporary:
                notarize(args.app.resolve(), notary, Path(temporary))
    except SigningError as error:
        print(f'macos-release-signing: {error}', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
