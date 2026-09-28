#!/usr/bin/env python3
"""Focused live status regressions; restore every mutation and relocated build cache."""
import difflib
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[4]
EVIDENCE = Path(__file__).resolve().parent
SOURCE = ROOT / 'src/adapters/supervisor/bridge.rs'
RESULTS = EVIDENCE / 'status-and-target-results.json'
summary = {}

def save():
    RESULTS.write_text(json.dumps(summary, indent=2) + '\n')

def run(label, scenario, extra=None):
    env = dict(os.environ, VW18_SCENARIO=scenario)
    env.update(extra or {})
    with (EVIDENCE / (label + '.log')).open('w') as log:
        log.write('scenario: ' + scenario + '\nCARGO_TARGET_DIR: ' + env.get('CARGO_TARGET_DIR', '(default)') + '\n')
        log.flush()
        result = subprocess.run(['scripts/test-systemd-supervisor.sh'], cwd=ROOT, env=env,
                                stdout=log, stderr=subprocess.STDOUT, timeout=360)
        log.write('exit_code: ' + str(result.returncode) + '\n')
    summary[label] = result.returncode
    save()
    return result.returncode

# A missing default target prevents accidentally passing with stale helper/rlib paths.
with tempfile.TemporaryDirectory(prefix='vw18-custom-target-') as temporary:
    custom = Path(temporary) / 'artifacts'
    default = ROOT / 'target'
    assert default.is_dir() and not custom.exists()
    default.rename(custom)
    try:
        summary['default_target_absent_before'] = not default.exists()
        assert run('custom-target-app-nonzero', 'app-nonzero', {'CARGO_TARGET_DIR': str(custom)}) == 0
        summary['default_target_absent_after'] = not default.exists()
        assert summary['default_target_absent_after']
    finally:
        assert not default.exists(), 'refuse to overwrite unexpected default build cache'
        custom.rename(default)
        summary['build_cache_restored'] = default.is_dir()
        save()
assert run('app-signal-baseline', 'app-signal') == 0
original = SOURCE.read_bytes()
summary['source_sha256_before'] = hashlib.sha256(original).hexdigest()
mutations = [
    ('nonzero-as-zero', 'app-nonzero', '                        NONZERO\n', '                        ZERO\n', 'ExecutionNonzero'),
    ('signal-as-zero', 'app-signal', '                    SIGNAL\n', '                    ZERO\n', 'ExecutionSignaled'),
]
try:
    for label, scenario, before, after, reason in mutations:
        text = original.decode()
        assert text.count(before) == 1
        mutated = text.replace(before, after)
        (EVIDENCE / (label + '.diff')).write_text(''.join(difflib.unified_diff(
            text.splitlines(keepends=True), mutated.splitlines(keepends=True),
            fromfile='a/src/adapters/supervisor/bridge.rs', tofile='b/src/adapters/supervisor/bridge.rs')))
        SOURCE.write_text(mutated)
        assert run(label, scenario) == 101
        log = (EVIDENCE / (label + '.log')).read_text()
        unit = re.search(r'provider: (vw18-harness-[^\s]+\.service)', log).group(1)
        journal = subprocess.run(['journalctl', '--user', '--unit', unit, '--no-pager'],
                                 cwd=ROOT, text=True, capture_output=True, timeout=15, check=True)
        (EVIDENCE / (label + '-provider.log')).write_text(journal.stdout.rstrip() + '\n')
        assert reason in journal.stdout and 'Completed' in journal.stdout
        assert 'assertion `left == right` failed' in journal.stdout
        assert 'test result: FAILED' in log
        summary[label + '-classification'] = 'caught by exact application status assertion in provider journal; outer harness fails its completion barrier after that panic; incorrect Completed versus required ' + reason
        SOURCE.write_bytes(original)
        save()
finally:
    SOURCE.write_bytes(original)
    summary['source_sha256_restored'] = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    summary['source_restored'] = SOURCE.read_bytes() == original
    save()
for mode in ['app-nonzero', 'app-signal', 'helper-failure', 'failed-launch-recovery']:
    assert run(mode + '-restored', mode) == 0
print(json.dumps(summary, indent=2))
