import gzip
import hashlib
import json
import os
import signal
from pathlib import Path
import subprocess
import time

def run_command(command, log, env, timeout):
    process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                               env=env, start_new_session=True)
    try:
        return process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        # Cargo/test descendants share this dedicated group. Kill all of them
        # before the caller restores mutated source or starts another check.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        return 124

root = Path.cwd()
phase = os.environ.get('STORY21_PHASE', 'parent')
out = root / 'docs/implementation/2-1-evidence' / phase
out.mkdir(parents=True, exist_ok=True)
checks = [
    ('format', ['cargo', 'fmt', '--all', '--', '--check'], 120),
    ('all-targets', ['cargo', 'test', '--all-targets', '--offline', '--locked'], 1200),
    ('msrv-all-targets', ['rustup', 'run', '1.88.0', 'cargo', 'test', '--all-targets', '--offline', '--locked'], 1200),
    ('clippy', ['cargo', 'clippy', '--all-targets', '--all-features', '--offline', '--locked', '--', '-D', 'warnings'], 1200),
    ('agents', ['cargo', 'test', '--offline', '--locked', '--lib', 'agent_'], 900),
    ('persistence', ['cargo', 'test', '--offline', '--locked', '--lib', 'provider_store::'], 900),
    ('human-integrations', ['cargo', 'test', '--offline', '--locked', '--test', 'human_cli', '--test', 'direct_request', '--test', 'provider_session'], 900),
    ('real-systemd', ['scripts/test-systemd-supervisor.sh'], 1000),
    ('build-human-cli', ['cargo', 'build', '--offline', '--locked', '--bin', 'vw-access'], 1200),
    ('browser', ['node', 'tests/ui/direct-request.mjs'], 600),
    ('diff-check', ['git', 'diff', '--check'], 120),
]
selected = os.environ.get('STORY21_CHECKS')
if selected is not None:
    names = selected.split(',')
    assert len(set(names)) == len(names) and all(n in {c[0] for c in checks} for n in names), names
    checks = [c for c in checks if c[0] in names]
env = os.environ.copy()
env['RUST_TEST_THREADS'] = '4'
env['CARGO_BUILD_JOBS'] = '2'
env['CARGO_NET_OFFLINE'] = 'true'

def manifest():
    paths = sorted(set(subprocess.check_output(['git', 'ls-files', '-co', '--exclude-standard'], text=True).splitlines()))
    return {p: hashlib.sha256((root / p).read_bytes()).hexdigest() for p in paths
            if (p.startswith(('src/', 'tests/', 'scripts/', 'systemd/')) or p in ('Cargo.toml', 'Cargo.lock'))
            and (root / p).is_file()}

original = manifest()
(out / 'source-hashes.json').write_text(json.dumps(original, indent=2) + '\n')
results = []
for name, command, timeout in checks:
    assert manifest() == original, 'Source changed before ' + name
    start = time.monotonic()
    log_path = out / (name + '.log')
    print('START ' + name, flush=True)
    with log_path.open('w') as log:
        code = run_command(command, log, env, timeout)
    result = dict(name=name, command=command, exit=code, seconds=round(time.monotonic()-start, 2))
    results.append(result)
    (out / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
    print(json.dumps(result), flush=True)
    assert manifest() == original, 'Source changed during ' + name
    if code:
        print(log_path.read_text()[-10000:], flush=True)
        raise SystemExit(code)
print('Selected verification checks complete; source hashes unchanged.', flush=True)
