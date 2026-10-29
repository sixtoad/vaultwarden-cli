#!/usr/bin/env python3
"""Build-derived desktop bundle contract and exact source provenance."""
import argparse
import hashlib
import importlib.util
import json
import os
import platform as host_platform
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location('artifact', Path(__file__).with_name('desktop-companion-artifact.py'))
artifact = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(artifact)


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
        inputs[name] = artifact.digest(path) if path.is_file() else None
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


def build_commands(repo, platform):
    environment = dict(os.environ)
    if platform == 'windows':
        # Copied launchers and command EXEs must not depend on a developer's
        # globally installed VC redistributable or DLL search PATH.
        environment['RUSTFLAGS'] = environment.get('RUSTFLAGS', '') + ' -C target-feature=+crt-static'
    commands = ['vaultwarden-cli']
    if platform == 'linux':
        commands += ['vw-access', 'vaultwarden-accessd', 'vaultwarden-access-exec']
    subprocess.run(['cargo', 'build', '--release', '--locked', *sum((['--bin', name] for name in commands), [])], cwd=repo, env=environment, check=True)
    subprocess.run(['cargo', 'build', '--release', '--locked', '--manifest-path', str(repo / 'companion/rust/Cargo.toml'), '--bin', 'companion-command', '--target-dir', str(repo / 'companion/rust/target')], cwd=repo, env=environment, check=True)
    return commands


def populate(repo, root, platform, source):
    suffix = '.exe' if platform == 'windows' else ''
    command_dir = root / ('Contents/Helpers' if platform == 'macos' else 'commands')
    command_dir.mkdir(parents=True, exist_ok=True)
    commands = ['vaultwarden-cli'] + (['vw-access', 'vaultwarden-accessd', 'vaultwarden-access-exec'] if platform == 'linux' else [])
    cargo_target = Path(os.environ.get('CARGO_TARGET_DIR', str(repo / 'target')))
    for command in commands:
        shutil.copy2(cargo_target / 'release' / (command + suffix), command_dir / (command + suffix))
    shutil.copy2(repo / 'companion/rust/target/release' / ('companion-command' + suffix), command_dir / ('companion-command' + suffix))
    if platform == 'macos':
        signing = subprocess.run(['/usr/bin/codesign', '-dv', str(root)], capture_output=True, text=True, check=True)
        if 'Signature=adhoc' not in signing.stderr:
            raise ValueError('Development bundler refuses to replace a distribution signature; use the publisher signing pipeline')
        for command in command_dir.iterdir():
            subprocess.run(['/usr/bin/codesign', '--force', '--sign', '-', str(command)], check=True)
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
        'architecture': {'arm64': 'aarch64', 'AMD64': 'x86_64'}.get(host_platform.machine(), host_platform.machine()),
        'app_version': next(line.removeprefix('version: ').strip() for line in (repo / 'companion/pubspec.yaml').read_text().splitlines() if line.startswith('version: ')),
        'core_version': tomllib.loads((repo / 'companion/rust/Cargo.toml').read_text())['package']['version'],
        'cli_version': tomllib.loads((repo / 'Cargo.toml').read_text())['package']['version'],
        'source_revision': source['revision'], 'source_inputs_sha256': source['inputs_sha256'],
        'entrypoint': 'lib/main.dart',
        'commands': {name: (command_dir / (name + suffix)).relative_to(root).as_posix() for name in ['vaultwarden-cli'] + (['vw-access'] if platform == 'linux' else [])},
        'roles': {'protected_requesting': platform == 'linux', 'desktop_approval': platform == 'macos', 'protected_provider': platform == 'linux', 'vault_cli': True},
        'payloads': payloads, 'links': links,
    }
    destination = root / ('Contents/Resources/bundle.json' if platform == 'macos' else 'bundle.json')
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(manifest, indent=2) + '\n')
    if platform == 'macos':
        # Preserve Flutter's sandbox and selected-file entitlements. Nested code
        # is signed before manifest hashing; only the outer app is resealed.
        subprocess.run(['/usr/bin/codesign', '--force', '--sign', '-', '--preserve-metadata=identifier,entitlements,flags,runtime', str(root)], check=True)
        subprocess.run(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(root)], check=True)
    verify(root, manifest)
    return manifest


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
    parser.add_argument('action', choices=['before', 'commands', 'package'])
    parser.add_argument('platform', choices=['macos', 'windows', 'linux'])
    parser.add_argument('evidence', type=Path)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    evidence = args.evidence.resolve()
    if args.action == 'before':
        checkpoint(repo, evidence, 'before')
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
        (evidence / 'bundle.json').write_text(json.dumps(manifest, indent=2) + '\n')
        archive = artifact.package(root, evidence, args.platform, source['revision'], source['source_dirty'])
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
