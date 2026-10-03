import os,subprocess,json,time,pathlib,hashlib
root=pathlib.Path.cwd();out=root/'docs/implementation/1-9-evidence/native-ci-review';out.mkdir(parents=True,exist_ok=True)
env=os.environ.copy();env['STORY19_EVIDENCE_PHASE']='native-ci-review';env['RUST_TEST_THREADS']='4';env['CARGO_NET_OFFLINE']='true'
workflow=(root/'.github/workflows/ci.yml').read_bytes()
(out/'workflow.sha256').write_text(hashlib.sha256(workflow).hexdigest()+'  .github/workflows/ci.yml\n')
subprocess.run(['python3','docs/implementation/1-9-evidence/verification-runner.py'],env=env,check=True)
results=[]
for toolchain,prefix in [('stable',[]),('rust-1.88',['rustup','run','1.88.0'])]:
 for features,flags in [('default',[]),('all',['--all-features']),('none',['--no-default-features'])]:
  name=toolchain+'-docs-'+features;command=prefix+['cargo','test','--workspace','--doc','--offline','--locked']+flags
  start=time.monotonic()
  with (out/(name+'.log')).open('w') as log:code=subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=900).returncode
  result=dict(name=name,command=command,exit=code,seconds=round(time.monotonic()-start,2));results.append(result)
  (out/'doc-results.json').write_text(json.dumps(results,indent=2)+'\n');print(json.dumps(result),flush=True)
  if code:raise SystemExit(code)
assert (root/'.github/workflows/ci.yml').read_bytes()==workflow, 'Workflow changed during verification'
subprocess.run(['git','diff','--check'],check=True)
print('Full final verification and all six documentation-test configurations completed.',flush=True)
