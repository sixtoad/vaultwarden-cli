#!/usr/bin/env python3
"""Build-derived desktop bundle contract and exact source provenance."""
import argparse
import hashlib
import importlib.util
import json
import os
import platform as host_platform
import plistlib
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tomllib

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location('artifact', Path(__file__).with_name('desktop-companion-artifact.py'))
artifact = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(artifact)
SIGNING_SPEC = importlib.util.spec_from_file_location('release_signing', Path(__file__).with_name('macos-release-signing.py'))
release_signing = importlib.util.module_from_spec(SIGNING_SPEC)
SIGNING_SPEC.loader.exec_module(release_signing)


def git(repo, *args):
    return subprocess.check_output(['git', *args], cwd=repo)


def provenance(repo):
    paths = git(repo, 'ls-files', '-z', '--cached', '--others', '--exclude-standard').split(b'\0')
    inputs = {}
    for raw in sorted(set(paths)):
        if not raw:
            continue
        name = os.fsdecode(raw)
        path = repo / name
        if path.is_symlink():
            inputs[name] = {'kind': 'symlink', 'mode': stat.S_IMODE(path.lstat().st_mode), 'target': os.readlink(path)}
        elif path.is_file():
            inputs[name] = {'kind': 'file', 'mode': stat.S_IMODE(path.stat().st_mode), 'sha256': artifact.digest(path)}
        else:
            inputs[name] = None
    status = git(repo, 'status', '--porcelain=v1', '-z')
    return {
        'revision': git(repo, 'rev-parse', 'HEAD').decode().strip(),
        'source_dirty': bool(status),
        'status_porcelain_z': os.fsdecode(status),
        'diff': git(repo, 'diff', '--binary', 'HEAD', '--').decode('utf-8', errors='replace'),
        'inputs': inputs,
        'inputs_sha256': hashlib.sha256(json.dumps(inputs, sort_keys=True, ensure_ascii=True).encode()).hexdigest(),
    }


def checkpoint(repo, evidence, name):
    evidence.mkdir(parents=True, exist_ok=True)
    state = provenance(repo)
    (evidence / f'source-{name}.json').write_text(json.dumps(state, indent=2, ensure_ascii=True) + '\n')
    return state


def host_architecture():
    """Host command architecture in Rust's spelling (aarch64/x86_64)."""
    machine = host_platform.machine()
    return {'arm64': 'aarch64', 'AMD64': 'x86_64'}.get(machine, machine)


UNSUPPORTED_INTEL_MAC = 'Intel (x86_64) macOS is no longer supported or built; build the macOS bundle on Apple Silicon (arm64)'


def require_supported(platform, architecture):
    """Refuse Intel macOS (owner decision 2026-11-10): only Apple Silicon is built.

    Linux and Windows x86_64 are unaffected; only Intel *Mac* is dropped.
    """
    if platform == 'macos' and architecture != 'aarch64':
        raise ValueError(f'{UNSUPPORTED_INTEL_MAC} (architecture: {architecture})')


def protected_commands(platform, architecture):
    """Protected request/provider binaries the bundle ships, by platform.

    Linux ships the systemd helper `vaultwarden-access-exec`. The native macOS
    provider does not use it (the helper exits 1 off Linux). macOS bundles are
    Apple Silicon only and always carry the protected commands; an Intel macOS
    architecture is refused. Windows has none.
    """
    require_supported(platform, architecture)
    if platform == 'linux':
        return ['vw-access', 'vaultwarden-accessd', 'vaultwarden-access-exec']
    if platform == 'macos':
        return ['vw-access', 'vaultwarden-accessd']
    return []


def build_commands(repo, platform):
    environment = dict(os.environ)
    if platform == 'windows':
        # Copied launchers and command EXEs must not depend on a developer's
        # globally installed VC redistributable or DLL search PATH.
        environment['RUSTFLAGS'] = environment.get('RUSTFLAGS', '') + ' -C target-feature=+crt-static'
    commands = ['vaultwarden-cli', *protected_commands(platform, host_architecture())]
    subprocess.run(['cargo', 'build', '--release', '--locked', *sum((['--bin', name] for name in commands), [])], cwd=repo, env=environment, check=True)
    subprocess.run(['cargo', 'build', '--release', '--locked', '--manifest-path', str(repo / 'companion/rust/Cargo.toml'), '--bin', 'companion-command', '--target-dir', str(repo / 'companion/rust/target/command-launcher')], cwd=repo, env=environment, check=True)
    return commands


def build_app(repo, platform, evidence):
    environment = dict(os.environ)
    # Windows CreateProcess does not expand the bare name to Flutter's batch
    # launcher as the calling shell does. Pass its resolved path explicitly.
    launcher = 'flutter.bat' if platform == 'windows' else 'flutter'
    flutter = shutil.which(launcher, path=environment.get('PATH'))
    if flutter is None:
        raise FileNotFoundError(f'Flutter launcher not found on PATH: {launcher}')
    if platform == 'macos':
        # The macOS app is Apple Silicon only (companion/macos/Runner/Configs
        # sets ARCHS = arm64); pin it here too so the package and its
        # host-native commands always agree. Intel hosts are refused.
        require_supported(platform, host_architecture())
        lines = []
        previous = environment.get('XCODE_XCCONFIG_FILE')
        if previous:
            previous = str(Path(previous).resolve())
            if any(c in previous for c in '\n\r"'):
                raise ValueError('unsafe Xcode configuration path')
            lines.append(f'#include "{previous}"')
        lines += ['ARCHS = arm64', 'ONLY_ACTIVE_ARCH = YES']
        config = evidence / 'desktop-architecture.xcconfig'
        config.write_text('\n'.join(lines) + '\n')
        environment['XCODE_XCCONFIG_FILE'] = str(config)
    subprocess.run([flutter, 'build', platform, '--release', '--target', 'lib/main.dart'], cwd=repo / 'companion', env=environment, check=True)


def populate(repo, root, platform, source):
    suffix = '.exe' if platform == 'windows' else ''
    architecture = host_architecture()
    # Refuse an unsupported platform before anything is written into the bundle.
    protected = protected_commands(platform, architecture)
    command_dir = root / ('Contents/Helpers' if platform == 'macos' else 'commands')
    command_dir.mkdir(parents=True, exist_ok=True)
    commands = ['vaultwarden-cli', *protected]
    cargo_target = Path(os.environ.get('CARGO_TARGET_DIR', str(repo / 'target')))
    for command in commands:
        shutil.copy2(cargo_target / 'release' / (command + suffix), command_dir / (command + suffix))
    shutil.copy2(repo / 'companion/rust/target/command-launcher/release' / ('companion-command' + suffix), command_dir / ('companion-command' + suffix))
    if platform == 'macos':
        built = subprocess.run(['/usr/bin/codesign', '-dv', str(root)], capture_output=True, text=True, check=True)
        if 'Signature=adhoc' not in built.stderr:
            raise ValueError('Development bundler refuses to replace a distribution signature; use the publisher signing pipeline')
        expected_arch = 'arm64'
        for executable in [root / 'Contents/MacOS/companion_slice', *command_dir.iterdir()]:
            actual = subprocess.check_output(['/usr/bin/lipo', '-archs', str(executable)], text=True).split()
            if actual != [expected_arch]:
                raise ValueError(f'Application/command architecture mismatch: {executable}: {actual}; expected {expected_arch}')
        signing = release_signing.signing_from_env(os.environ)
        if signing is None:
            print('macOS development build: Developer ID signing is not configured; commands and app are signed ad hoc', file=sys.stderr)
            for command in command_dir.iterdir():
                subprocess.run(['/usr/bin/codesign', '--force', '--sign', '-', str(command)], check=True)
        else:
            # Developer ID (#62): every nested signature and the embedded profile
            # exist before the manifest hashes the payloads.
            release_entitlements = release_entitlements_for(repo, root, signing)
            release_signing.sign_nested(root, signing)
    app = {'macos': 'Contents/MacOS/companion_slice', 'windows': 'companion_slice.exe', 'linux': 'companion_slice'}[platform]
    core = {'macos': 'Contents/Frameworks/libcompanion_core.dylib', 'windows': 'companion_core.dll', 'linux': 'lib/libcompanion_core.so'}[platform]
    # All regular app/runtime/resources are bound. Framework links are recorded
    # separately and must remain internal; outer signature files are bound by
    # codesign and by the external archive inventory after resealing.
    payloads, links = [], {}
    for item in sorted(root.rglob('*')):
        path = item.relative_to(root).as_posix()
        if path.endswith('/bundle.json') or path == 'bundle.json' or '_CodeSignature' in item.parts:
            continue
        if item.is_symlink():
            if not item.resolve().is_relative_to(root.resolve()):
                raise ValueError('external framework link')
            links[path] = os.readlink(item)
        elif item.is_file():
            payloads.append({'path': path, 'sha256': '' if platform == 'macos' and path == app else artifact.digest(item), 'executable': bool(item.stat().st_mode & 0o111) if os.name != 'nt' else path.endswith('.exe')})
    manifest = {
        'schema': 1, 'command_abi': 1, 'platform': platform,
        'architecture': architecture,
        'app_version': next(line.removeprefix('version: ').strip() for line in (repo / 'companion/pubspec.yaml').read_text().splitlines() if line.startswith('version: ')),
        'core_version': tomllib.loads((repo / 'companion/rust/Cargo.toml').read_text())['package']['version'],
        'cli_version': tomllib.loads((repo / 'Cargo.toml').read_text())['package']['version'],
        'source_revision': source['revision'], 'source_inputs_sha256': source['inputs_sha256'],
        'entrypoint': 'lib/main.dart',
        'commands': {name: (command_dir / (name + suffix)).relative_to(root).as_posix() for name in ['vaultwarden-cli'] + (['vw-access'] if protected else [])},
        'roles': {'protected_requesting': bool(protected), 'desktop_approval': platform == 'macos', 'protected_provider': bool(protected), 'vault_cli': True},
        'payloads': payloads, 'links': links,
    }
    destination = root / ('Contents/Resources/bundle.json' if platform == 'macos' else 'bundle.json')
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(manifest, indent=2) + '\n')
    if platform == 'macos':
        # Preserve Flutter's sandbox and selected-file entitlements. Nested code
        # is signed before manifest hashing; only the outer app is resealed.
        if signing is None:
            subprocess.run(['/usr/bin/codesign', '--force', '--sign', '-', '--preserve-metadata=identifier,entitlements,flags,runtime', str(root)], check=True)
            subprocess.run(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(root)], check=True)
        else:
            release_signing.sign_app(root, signing, release_entitlements)
            release_signing.verify(root, signing.team, release_entitlements)
        verify_macos_entitlements(root)
    verify(root, manifest)
    return manifest


def release_entitlements_for(repo, root, signing):
    """Checked profile embedded; the app's minimum entitlements: Release.entitlements
    (exactly what Flutter's release build signed) plus the profile's identity."""
    with (repo / 'companion/macos/Runner/Release.entitlements').open('rb') as stream:
        declared = plistlib.load(stream)
    built = release_signing.entitlements_of(root)
    # Xcode adds get-task-allow to its ad hoc build; the Developer ID app never has it.
    built.pop('com.apple.security.get-task-allow', None)
    if built != declared:
        raise ValueError(f'the built app entitlements {sorted(built)} differ from Release.entitlements {sorted(declared)}')
    bundle_id = release_signing.bundle_identifier(root)
    granted = release_signing.embed_profile(root, signing, bundle_id)
    return release_signing.app_entitlements(declared, signing.team, bundle_id, granted)


def signing_variant(platform):
    """Archive variant and signing record: development, signed (not notarized) or notarized."""
    if platform != 'macos':
        return 'development', None, None
    signing = release_signing.signing_from_env(os.environ)
    if signing is None:
        return 'development', None, None
    notary = release_signing.notary_from_env(os.environ)
    return ('notarized' if notary else 'signed'), signing, notary


def archive_architecture(platform, architecture):
    """Archive-name qualifier: the macOS archive states arm64 (the only one built)."""
    if platform != 'macos':
        return None
    require_supported(platform, architecture)
    return 'arm64'


def check_expected_architecture(root, manifest, expected):
    """Fail a build whose host or helper set is not the one the job promises.

    A release job that publishes the arm64 macOS archive must not silently ship
    another architecture if its runner changes. Intel (x86_64) macOS is not
    supported, so a job or manifest naming it is refused outright.
    """
    if not expected:
        if any(os.environ.get(key, '').lower() == 'true' for key in ('CI', 'GITHUB_ACTIONS')):
            raise ValueError('DESKTOP_EXPECTED_ARCHITECTURE is required in CI (arm64 or x86_64)')
        print('warning: DESKTOP_EXPECTED_ARCHITECTURE is not set; the bundle architecture is not checked', file=sys.stderr)
        return
    expected = {'arm64': 'aarch64', 'AMD64': 'x86_64'}.get(expected, expected)
    if expected not in ('aarch64', 'x86_64'):
        raise ValueError(f'unsupported expected architecture: {expected}')
    require_supported(manifest['platform'], expected)
    require_supported(manifest['platform'], manifest['architecture'])
    if manifest['architecture'] != expected:
        raise ValueError(f"bundle architecture {manifest['architecture']} is not the expected {expected}")
    platform = manifest['platform']
    suffix = '.exe' if platform == 'windows' else ''
    command_dir = root / ('Contents/Helpers' if platform == 'macos' else 'commands')
    protected = protected_commands(platform, expected)
    shipped = sorted(p.name for p in command_dir.iterdir())
    wanted = sorted(name + suffix for name in ['companion-command', 'vaultwarden-cli', *protected])
    if shipped != wanted:
        raise ValueError(f'bundled commands {shipped} are not the expected {wanted}')
    if ('vw-access' in manifest['commands']) != bool(protected) or manifest['roles']['protected_provider'] != bool(protected):
        raise ValueError('advertised protected commands do not match the expected architecture')


def verify_macos_entitlements(root):
    result = subprocess.run(['/usr/bin/codesign', '-d', '--entitlements', ':-', str(root)], capture_output=True, check=True)
    entitlements = plistlib.loads(result.stdout)
    for key in ['com.apple.security.app-sandbox', 'com.apple.security.files.user-selected.read-write', 'com.apple.security.files.user-selected.executable']:
        if entitlements.get(key) is not True:
            raise ValueError('Missing required sandbox/user-selected executable entitlement: ' + key)


def verify(root, manifest):
    if manifest['schema'] != 1 or manifest['command_abi'] != 1 or manifest['entrypoint'] != 'lib/main.dart':
        raise ValueError('incompatible bundle contract')
    for entry in manifest['payloads']:
        path = root / entry['path']
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root.resolve()):
            raise ValueError('missing or unsafe payload')
        if entry['sha256'] and artifact.digest(path) != entry['sha256']:
            raise ValueError('damaged payload')
        if entry['executable'] and os.name != 'nt' and not path.stat().st_mode & 0o111:
            raise ValueError('non-executable payload')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['before', 'commands', 'app', 'package'])
    parser.add_argument('platform', choices=['macos', 'windows', 'linux'])
    parser.add_argument('evidence', type=Path)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    evidence = args.evidence.resolve()
    if args.action == 'before':
        checkpoint(repo, evidence, 'before')
    elif args.action == 'app':
        build_app(repo, args.platform, evidence)
    elif args.action == 'commands':
        build_commands(repo, args.platform)
    else:
        source = checkpoint(repo, evidence, 'after')
        baseline = json.loads((evidence / 'source-before.json').read_text())
        if baseline['inputs'] != source['inputs']:
            changed = sorted(k for k in baseline['inputs'].keys() | source['inputs'].keys() if baseline['inputs'].get(k) != source['inputs'].get(k))
            (evidence / 'source-changed-paths.json').write_text(json.dumps(changed, indent=2) + '\n')
            raise RuntimeError('Build inputs changed during packaging: ' + ', '.join(changed))
        root, _ = artifact.locate(repo, args.platform)
        manifest = populate(repo, root, args.platform, source)
        check_expected_architecture(root, manifest, os.environ.get('DESKTOP_EXPECTED_ARCHITECTURE', ''))
        variant, signing, notary = signing_variant(args.platform)
        if variant == 'notarized':
            release_signing.notarize(root, notary, evidence / 'notarization')
            release_signing.verify(root, signing.team)
            verify(root, manifest)
        elif variant == 'signed':
            print('::warning::Developer ID signed but NOT notarized: no notary credentials are configured; Gatekeeper will refuse this download', file=sys.stderr)
        (evidence / 'bundle.json').write_text(json.dumps(manifest, indent=2) + '\n')
        record = None if signing is None else {'kind': 'developer-id', 'team_id': signing.team, 'notarized': variant == 'notarized'}
        archive = artifact.package(root, evidence, args.platform, source['revision'], source['source_dirty'],
                                   architecture=archive_architecture(args.platform, manifest['architecture']),
                                   variant=variant, signing=record)
        # Exercise the production launcher against the freshly extracted archive,
        # not the build directory or a self-exiting GUI test entrypoint.
        import tarfile
        import tempfile
        with tempfile.TemporaryDirectory(prefix='packaged-commands-') as temporary:
            with tarfile.open(archive) as stream:
                stream.extractall(temporary, filter='fully_trusted')
            extracted = next(Path(temporary).iterdir())
            environment = dict(os.environ, COMPANION_TEST_BUNDLE=str(extracted))
            subprocess.run(['cargo', 'test', '--locked', '--manifest-path', str(repo / 'companion/rust/Cargo.toml'), 'installation::tests::packaged_bundle_command_invocation', '--', '--ignored', '--exact', '--nocapture'], cwd=repo, env=environment, check=True)



if __name__ == '__main__':
    main()
