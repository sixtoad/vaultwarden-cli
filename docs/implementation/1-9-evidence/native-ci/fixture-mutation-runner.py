import json, pathlib, subprocess, time, hashlib
root = pathlib.Path.cwd()
binary = root / 'tests/fixtures/protected-exit-x86_64.bin'
original = binary.read_bytes()
out = root / 'docs/implementation/1-9-evidence/native-ci'
out.mkdir(parents=True, exist_ok=True)
command = ['cargo','test','--offline','--locked','--lib','adapters::execution::linux::tests::native_argument_environment_oracle_has_independent_positive_and_negative_controls','--','--exact','--nocapture']
results=[]
try:
    for name, pattern, offset in [
        ('omit-argument-content-guard', bytes.fromhex('81386d61726b751d'), 6),
        ('omit-argument-terminator-guard', bytes.fromhex('807804007517'), 4),
        ('omit-environment-guard', bytes.fromhex('48837c2420007507'), 6),
    ]:
        assert original.count(pattern)==1, name
        at=original.index(pattern)+offset
        binary.write_bytes(original[:at]+b'\x90\x90'+original[at+2:])
        start=time.monotonic()
        with (out/(name+'.log')).open('w') as log:
            completed=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,timeout=180)
        content=(out/(name+'.log')).read_text()
        caught=completed.returncode==101 and 'assertion `left == right` failed' in content and 'test result: FAILED' in content
        results.append({'mutation':name,'returncode':completed.returncode,'classification':'caught' if caught else 'unexpected','seconds':round(time.monotonic()-start,2)})
        print(json.dumps(results[-1]),flush=True)
        binary.write_bytes(original)
        if not caught: raise SystemExit('mutation not caught: '+name)
finally:
    binary.write_bytes(original)
    (out/'fixture-mutations.json').write_text(json.dumps({'command':command,'restored_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'results':results},indent=2)+'\n')
print('All three fixture guard mutations caught; fixture bytes restored.',flush=True)
