import json, pathlib, subprocess, time
root=pathlib.Path.cwd(); out=root/'docs/implementation/1-8-evidence/review-1'; out.mkdir(parents=True,exist_ok=True)
checks=[
 ('formatting',['cargo','fmt','--all','--','--check'],120),
 ('static-contracts',['python3','docs/implementation/1-8-evidence/static-contracts.py'],30),
 ('strict-clippy',['cargo','clippy','--all-targets','--all-features','--offline','--locked','--','-D','warnings'],300),
 ('stable-all-targets',['env','RUST_TEST_THREADS=4','cargo','test','--all-targets','--offline','--locked'],1200),
 ('rust-1.88-all-targets',['env','RUST_TEST_THREADS=4','rustup','run','1.88.0','cargo','test','--all-targets','--offline','--locked'],1200),
 ('named-contracts',['cargo','test','--offline','--locked','--lib','contract','--','--test-threads=4'],180),
 ('browser',['node','tests/ui/direct-request.mjs'],300),
 ('real-final',['scripts/test-systemd-supervisor.sh'],900),
]
results=[]
for name,command,limit in checks:
 start=time.monotonic()
 with (out/(name+'.log')).open('w') as log:
  try: code=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,timeout=limit).returncode
  except subprocess.TimeoutExpired: code=124
 result=dict(name=name,command=command,exit=code,seconds=round(time.monotonic()-start,2))
 results.append(result); (out/'verification-results.json').write_text(json.dumps(results,indent=2)+'\n')
 print(json.dumps(result),flush=True)
 if code: raise SystemExit(code)
