import difflib, hashlib, json, pathlib, subprocess, time
root=pathlib.Path.cwd()
out=root/'docs/implementation/1-8-evidence/semantic'
out.mkdir(parents=True, exist_ok=True)
items=[
('cleanup-lock-order','src/access/application.rs','        drop(active);\n','', 'access::application::tests::uncertain_cleanup_releases_execution_registry_before_closing_admission'),
('zero-packet-rights','src/adapters/supervisor/bridge.rs','    if count < 0 {\n        return Err(BridgeError);\n    }\n    // A zero-byte','    if count <= 0 {\n        return Err(BridgeError);\n    }\n    // A zero-byte','adapters::supervisor::bridge::tests::zero_length_packet_closes_every_received_descriptor'),
('required-dependency','src/adapters/supervisor/manager.rs','        property("BindsTo", vec![config.provider.clone()]),\n','', 'adapters::supervisor::manager::tests::exact_typed_manager_contract_and_no_secret_properties'),
('release-authority','src/access/application.rs',None,None,'access::direct_request_tests::final_release_revalidates_authority_after_supervisor_setup'),
('cleanup-terminal','src/access/application.rs','if report.cleanup == CleanupEvidence::Uncertain {','if false {','access::direct_request_tests::uncertain_cleanup_closes_admission_and_never_persists_terminal'),
('revocation-lifecycle','src/access/provider_store.rs','if !recovered\n','if false\n','access::direct_request_tests::running_is_observed_before_reaping_and_lock_waits_without_holding_authority'),
('recovery-before-validation','src/access/provider_store.rs','        cleanup().map_err(|_error| error(ProviderDiagnostic::PersistenceFailure))?;','        drop(cleanup);','access::provider::tests::startup_cleanup_precedes_registered_image_integrity_validation'),
('actual-helper-parent','src/adapters/supervisor/bridge.rs','libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) == 0 && libc::getppid() == parent','libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) == 0','adapters::supervisor::bridge::tests::parent_death_before_and_after_prctl_uses_actual_helper_identity'),
]
results=[]
for name,file,old,new,test in items:
 p=root/file; baseline=p.read_text()
 command=['cargo','test','--offline','--locked','--lib',test,'--','--exact','--test-threads=1']
 def run(label):
  with (out/(name+'-'+label+'.log')).open('w') as log:
   try: return subprocess.run(command, stdout=log,stderr=subprocess.STDOUT,timeout=300).returncode
   except subprocess.TimeoutExpired: return 124
 base=run('baseline')
 if base: raise RuntimeError((name,'baseline',base))
 if name=='release-authority':
  a=baseline.index('        let mut authority =',baseline.index('impl ExecutionControl for ApplicationExecution'))
  b=baseline.index('        action()',a)
  mutated=baseline[:a]+baseline[b:]
 else:
  assert baseline.count(old)==1,(name,baseline.count(old))
  mutated=baseline.replace(old,new)
 (out/(name+'.diff')).write_text(''.join(difflib.unified_diff(baseline.splitlines(True),mutated.splitlines(True),fromfile=file,tofile=file)))
 try:
  p.write_text(mutated)
  result=run('mutant')
 finally: p.write_text(baseline)
 log=(out/(name+'-mutant.log')).read_text()
 classification='caught' if result==101 and 'test result: FAILED' in log else 'survived' if result==0 else 'timeout' if result==124 else 'compiler-or-infrastructure'
 results.append(dict(name=name,file=file,test=test,baseline_exit=base,mutant_exit=result,classification=classification,baseline_sha256=hashlib.sha256(baseline.encode()).hexdigest()))
 (out/'results.json').write_text(json.dumps(results,indent=2)+'\n')
 print(name,classification,flush=True)
 if classification!='caught': raise RuntimeError((name,classification))
