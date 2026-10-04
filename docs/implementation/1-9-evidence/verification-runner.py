import hashlib
import json
import os
from pathlib import Path
import subprocess
import shutil
import time

checks = [
    ('formatting', ['cargo', 'fmt', '--all', '--', '--check'], 120),
    ('stable-all-targets', ['cargo', 'test', '--all-targets', '--offline', '--locked'], 1800),
    ('rust-1.88-all-targets', ['rustup', 'run', '1.88.0', 'cargo', 'test', '--all-targets', '--offline', '--locked'], 1800),
    ('strict-clippy', ['cargo', 'clippy', '--all-targets', '--all-features', '--offline', '--locked', '--', '-D', 'warnings'], 600),
    ('human-integrations', ['cargo', 'test', '--offline', '--locked', '--test', 'human_cli', '--test', 'direct_request', '--test', 'provider_session'], 600),
    ('build-human-cli', ['cargo', 'build', '--offline', '--locked', '--bin', 'vw-access'], 300),
    ('browser', ['node', 'tests/ui/direct-request.mjs'], 360),
    ('real-systemd', ['scripts/test-systemd-supervisor.sh'], 1000),
]
env = os.environ.copy()
env['RUST_TEST_THREADS'] = '4'
env.setdefault('VW_UI_DEPS', '/tmp/vw-story14-browser/node_modules')
env.setdefault('CERTUTIL', '/tmp/vw-story13-nss/extracted/usr/bin/certutil')
env['CARGO_NET_OFFLINE'] = 'true'
required_count = len(checks)
selected = os.environ.get('STORY19_CHECKS')
if selected is not None:
    names = [name.strip() for name in selected.split(',')]
    known = {check[0] for check in checks}
    if any(not name or name not in known for name in names):
        raise SystemExit('STORY19_CHECKS must contain nonempty, known check names.')
    checks = [check for check in checks if check[0] in names]
if any(name == 'browser' for name, _, _ in checks):
    dependencies = Path(env['VW_UI_DEPS'])
    try:
        package = json.loads((dependencies / 'puppeteer-core/package.json').read_text())
        available = (dependencies / 'puppeteer-core' / package['main']).is_file()
        available &= (dependencies / 'axe-core/axe.min.js').is_file()
        available &= bool(shutil.which(env['CERTUTIL']))
        available &= bool(shutil.which(env.get('FIREFOX', '/usr/bin/firefox')))
        available &= bool(shutil.which('node'))
    except (OSError, ValueError, KeyError, TypeError):
        available = False
    if not available:
        raise SystemExit('Browser dependencies unavailable; check VW_UI_DEPS, CERTUTIL, FIREFOX and node.')
root = Path.cwd()
out = root / 'docs/implementation/1-9-evidence' / os.environ.get('STORY19_EVIDENCE_PHASE', 'parent')
out.mkdir(parents=True, exist_ok=True)
paths = sorted(set(subprocess.check_output(
    ['git', 'ls-files', '-co', '--exclude-standard'], text=True
).splitlines()))
paths = [p for p in paths if p.startswith(('src/', 'tests/', 'scripts/', 'systemd/'))
         or p in ('Cargo.toml', 'Cargo.lock')]
def manifest():
    return ''.join(hashlib.sha256((root / p).read_bytes()).hexdigest() + '  ' + p + '\n'
                   for p in paths if (root / p).is_file())
original = manifest()
(out / 'source.sha256').write_text(original)
results = []
for name, command, timeout in checks:
    start = time.monotonic()
    with (out / (name + '.log')).open('w') as log:
        try:
            code = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                                  env=env, timeout=timeout).returncode
        except subprocess.TimeoutExpired:
            code = 124
    result = dict(name=name, command=command, exit=code,
                  seconds=round(time.monotonic() - start, 2))
    results.append(result)
    (out / 'verification-results.json').write_text(json.dumps(results, indent=2) + '\n')
    print(json.dumps(result), flush=True)
    if code:
        raise SystemExit(code)
assert manifest() == original, 'Source changed during verification'
if len(checks) == required_count:
    print('All required parent verification jobs finished; source manifest unchanged.', flush=True)
else:
    print(f'Selected verification jobs finished ({len(checks)}/{required_count}); source manifest unchanged. Full required verification was not run.', flush=True)
