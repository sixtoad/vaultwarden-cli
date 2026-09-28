import pathlib,hashlib,json,subprocess,difflib
root=pathlib.Path.cwd();out=root/'docs/implementation/1-8-evidence/review-2-parent';out.mkdir(parents=True,exist_ok=True)
p=root/'src/adapters/supervisor/manager.rs';original=p.read_text();digest=hashlib.sha256(p.read_bytes()).hexdigest()
test='adapters::supervisor::manager::tests::proc_inventory_stops_at_the_entry_that_exhausts_the_remaining_budget'
items=[('entry-scan-budget','        if !has_budget() {\n            return Err(ExecutionError::CleanupUncertain);\n        }','',test),('final-scan-budget','    if !has_budget() {\n        return Err(ExecutionError::CleanupUncertain);\n    }','',test),('failed-unit-collection','        property("CollectMode", "inactive-or-failed".to_owned()),\n','', 'adapters::supervisor::manager::tests::exact_typed_manager_contract_and_no_secret_properties')]
results=[]
def run(name,label,test):
 with (out/(name+'-'+label+'.log')).open('w') as log:
  try: return subprocess.run(['cargo','test','--offline','--locked','--lib',test,'--','--exact','--test-threads=1'],stdout=log,stderr=subprocess.STDOUT,timeout=180).returncode
  except subprocess.TimeoutExpired:return 124
for name,old,new,test in items:
 baseline=run(name,'baseline',test);assert baseline==0,(name,baseline)
 assert original.count(old)==1,(name,original.count(old))
 mutant=original.replace(old,new)
 (out/(name+'.diff')).write_text(''.join(difflib.unified_diff(original.splitlines(True),mutant.splitlines(True),fromfile='src/adapters/supervisor/manager.rs',tofile='src/adapters/supervisor/manager.rs')))
 try:
  p.write_text(mutant);status=run(name,'mutant',test)
 finally:p.write_text(original)
 log=(out/(name+'-mutant.log')).read_text();classification='caught' if status==101 and 'test result: FAILED' in log else 'survived' if status==0 else 'infrastructure-or-timeout'
 results.append(dict(name=name,test=test,baseline_exit=baseline,mutant_exit=status,classification=classification,source_sha256=digest));(out/'mutation-results.json').write_text(json.dumps(results,indent=2)+'\n');print(name,classification,flush=True)
 assert classification=='caught',(name,classification)
assert hashlib.sha256(p.read_bytes()).hexdigest()==digest
print('All parent mutations caught and source restored',flush=True)
