import difflib, hashlib, json, os, shutil, subprocess, tempfile
from pathlib import Path
root = Path.cwd()
stage = Path(tempfile.mkdtemp(prefix='vw49-review-mutations-', dir=os.environ['TMPDIR']))
evidence = Path(tempfile.mkdtemp(prefix='vw49-review-mutation-evidence-', dir='/tmp'))
for name in ['src', 'tests', 'benches', 'scripts']:
    shutil.copytree(root/name, stage/name)
for name in ['Cargo.toml', 'Cargo.lock', 'README.md']:
    shutil.copy2(root/name, stage/name)
subprocess.run(['cp', '-a', '--reflink=auto', str(root/'target'), str(stage/'target')], check=True)
path = Path('src/access/application.rs')
original = (stage/path).read_text()
report = {'source_sha256': {str(p):hashlib.sha256((root/p).read_bytes()).hexdigest() for p in [path, Path('src/access/direct_request_tests.rs'), Path('src/adapters/supervisor/real_tests.rs')]}, 'cases': {}}
test = 'access::direct_request_tests::protected_create_final_post_serializes_both_cancellation_orderings'
unit = ['cargo', 'test', '--offline', '--lib', test, '--', '--exact', '--test-threads=1']
real = ['scripts/test-systemd-supervisor.sh']
def run(name, command, mutant=None):
    content = original if mutant is None else mutant
    (stage/path).write_text(content)
    if mutant is not None:
        assert mutant != original
        (evidence/(name+'.patch')).write_text(''.join(difflib.unified_diff(original.splitlines(True), mutant.splitlines(True), fromfile='a/'+str(path), tofile='b/'+str(path))))
    with (evidence/(name+'.log')).open('w') as log:
        result = subprocess.run(command, cwd=stage, env=dict(os.environ, VW18_SCENARIO='app-ssh-cancel'), stdout=log, stderr=subprocess.STDOUT, timeout=300)
    output = (evidence/(name+'.log')).read_text()
    caught = result.returncode != 0 and 'test result: FAILED' in output
    report['cases'][name] = {'exit_code': result.returncode, 'caught_by_test': caught if mutant is not None else None, 'command': command}
    (evidence/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    print(name, report['cases'][name], flush=True)
    assert caught if mutant is not None else result.returncode == 0, str(evidence)
run('baseline-producer-gate', unit)
start = original.index('                let write_gate = self\n')
end = original.index('                if !control.live_fast()', start)
mutant = original[:start] + original[end:]
mutant = mutant.replace('                drop(write_gate);\n', '', 1)
run('producer-write-gate-removed', unit, mutant)
run('baseline-ssh-marker', real)
needle = '.is_some_and(|material| material.mark_in_use().is_err())'
assert original.count(needle) == 1
run('application-ssh-mark-in-use-removed', real, original.replace(needle, '.is_some_and(|_material| false)'))
report['worktree_untouched'] = (root/path).read_text() == original
assert report['worktree_untouched']
(evidence/'report.json').write_text(json.dumps(report, indent=2)+'\n')
print('EVIDENCE='+str(evidence), flush=True)
