import hashlib,json,os,shutil,subprocess,tempfile
from pathlib import Path
root=Path.cwd()
stage=Path(tempfile.mkdtemp(prefix='future-access-mutations-',dir=os.environ['TMPDIR']))
evidence=Path(tempfile.mkdtemp(prefix='future-access-mutation-evidence-',dir='/tmp'))
for name in ['src','tests','benches']:
 shutil.copytree(root/name,stage/name)
for name in ['Cargo.toml','Cargo.lock','README.md']:
 shutil.copy2(root/name,stage/name)
subprocess.run(['cp','-a','--reflink=auto',str(root/'target'),str(stage/'target')],check=True)
app=Path('src/access/application.rs');manager=Path('src/adapters/supervisor/manager.rs')
originals={p:(stage/p).read_text() for p in [app,manager]}
release_test='access::direct_request_tests::final_release_revalidates_authority_after_supervisor_setup'
property_test='adapters::supervisor::manager::tests::exact_typed_manager_contract_and_no_secret_properties'
def run(name,test):
 with (evidence/(name+'.log')).open('w') as log:
  result=subprocess.run(['cargo','test','--offline','--lib',test,'--','--exact','--test-threads=1'],cwd=stage,stdout=log,stderr=subprocess.STDOUT,timeout=240)
 output=(evidence/(name+'.log')).read_text()
 return result.returncode,output
report={'source_sha256':{str(p):hashlib.sha256(originals[p].encode()).hexdigest() for p in originals},'cases':{}}
for name,test in [('baseline-release',release_test),('baseline-properties',property_test)]:
 code,output=run(name,test)
 if code!=0 or '1 passed' not in output: raise RuntimeError('baseline failed: '+str(evidence/name))
release=originals[app];start=release.index('    fn release(');end=release.index('    fn started(',start)
release=release[:start]+'''    fn release(&self, action: &mut dyn FnMut() -> Result<(), ExecutionError>) -> Result<(), ExecutionError> { action() }
'''+release[end:]
props=originals[manager]
mutants=[('release-bypasses-cancellation',app,release,release_test),('consumer-control-group-stop',manager,props.replace('property("KillMode", "none".to_owned())','property("KillMode", "control-group".to_owned())'),property_test),('provider-dependency-stop',manager,props.replace('property("Type", "exec".to_owned()),','property("Type", "exec".to_owned()),\n        property("BindsTo", vec![config.provider.clone()]),'),property_test),('consumer-runtime-expiry',manager,props.replace('property("RuntimeMaxUSec", u64::MAX)','property("RuntimeMaxUSec", 1_000_000u64)'),property_test)]
for name,path,mutated,test in mutants:
 for p,content in originals.items(): (stage/p).write_text(content)
 assert mutated!=originals[path]
 (stage/path).write_text(mutated)
 code,output=run(name,test)
 caught=code!=0 and 'test result: FAILED' in output and '1 failed' in output
 report['cases'][name]={'exit_code':code,'caught_by_test':caught,'test':test}
 print(name,report['cases'][name],flush=True)
 if not caught: raise RuntimeError('mutation not caught: '+str(evidence/name))
for p,content in originals.items():
 (stage/p).write_text(content)
 assert (root/p).read_text()==content,'worktree changed during verification'
report['worktree_untouched']=True
(evidence/'report.json').write_text(json.dumps(report,indent=2)+'\n')
print('EVIDENCE='+str(evidence),flush=True)
