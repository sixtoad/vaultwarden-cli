import hashlib, json, os, pathlib, re, signal, subprocess, sys, time
root = pathlib.Path('/home/sixtocantolla/sessions/day-to-day/vaultwarden-bind-ssh-key-fixed-operation')
phase, config = sys.argv[1:]
out = pathlib.Path('/tmp/vw-story31-parent') / phase
out.mkdir(exist_ok=False)
checks = json.loads(pathlib.Path(config).read_text())
def manifest():
    names = subprocess.check_output(['git', 'ls-files', '-co', '--exclude-standard'], cwd=root, text=True).splitlines()
    return {p: hashlib.sha256((root/p).read_bytes()).hexdigest() for p in sorted(set(names))
            if (root/p).is_file() and (p.startswith(('src/', 'tests/', 'scripts/', 'packaging/')) or p in ('Cargo.toml', 'Cargo.lock'))}
original = manifest()
(out/'source-hashes.json').write_text(json.dumps(original, indent=2)+'\n')
env = os.environ.copy()
env.update(CARGO_TARGET_DIR='/home/sixtocantolla/sessions/day-to-day/vaultwarden-cli/target', CARGO_BUILD_JOBS='2', RUST_TEST_THREADS='4', CARGO_NET_OFFLINE='true', VW_UI_DEPS='/tmp/vw-story21-ui/node_modules', CERTUTIL='/tmp/vw-story21-nss/extracted/usr/bin/certutil', FIREFOX='/usr/bin/firefox')
results = []
for check in checks:
    assert manifest() == original, 'source changed before check'
    print('START', check['name'], flush=True)
    started = time.monotonic()
    logfile = out/(check['name']+'.log')
    with logfile.open('w') as log:
        child = subprocess.Popen(check['command'], cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = child.wait(timeout=check.get('timeout', 1200))
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()
            code = 124
    content = logfile.read_text(errors='replace')
    totals = re.findall(r'test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;', content)
    result = dict(name=check['name'], command=check['command'], exit=code, seconds=round(time.monotonic()-started, 2), suites=totals)
    results.append(result)
    (out/'results.json').write_text(json.dumps(results, indent=2)+'\n')
    print(json.dumps(result), flush=True)
    assert manifest() == original, 'source changed during check'
    if code:
        print(content[-10000:], flush=True)
        sys.exit(code)
print('All selected checks finished; sources unchanged.', flush=True)
