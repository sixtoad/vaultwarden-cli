import hashlib, json, os, pathlib, subprocess, time
root=pathlib.Path.cwd()
out=root/'docs/implementation/2-1-evidence'/os.environ.get('STORY21_GENERATED_PHASE','generated')
out.mkdir(parents=True,exist_ok=True)
files=['src/access/agent_binding.rs','src/access/direct_request.rs','src/access/provider.rs','src/access/application.rs','src/access/provider_store.rs']
selection='AgentBinding::(validate|matches_os)|valid_label|valid_os_id|validate_registry|AgentOwner::matches|Provider::(check_administrator|agent_binding_for_peer|agent_current|agent_status)|ProviderApplication::(token_live|request_agent_live|await_agent_cleanup)'
selection=os.environ.get('STORY21_GENERATED_SELECTION',selection)
command=['cargo','mutants','--no-config','--in-place','--cargo-arg=--lib']
for path in files: command+=['--file',path]
command+=['--re',selection,'--output',str(out),'--timeout','120','--build-timeout','900','--','agent_']
env=os.environ.copy();env.update(CARGO_BUILD_JOBS='2',RUST_TEST_THREADS='4',CARGO_NET_OFFLINE='true')
original={path:hashlib.sha256((root/path).read_bytes()).hexdigest() for path in files}
(out/'source-hashes.json').write_text(json.dumps(original,indent=2)+'\n')
(out/'command.json').write_text(json.dumps(command,indent=2)+'\n')
start=time.monotonic()
with (out/'campaign.log').open('w') as log:
    code=subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT).returncode
result=dict(command=command,exit=code,seconds=round(time.monotonic()-start,2))
(out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
assert original=={path:hashlib.sha256((root/path).read_bytes()).hexdigest() for path in files},'Sources not restored'
print(json.dumps(result),flush=True)
raise SystemExit(code)
