import difflib, hashlib, json, pathlib, subprocess, time, os
root=pathlib.Path.cwd()
out=root/'docs/implementation/1-8-evidence/review-1/semantic'
out.mkdir(parents=True, exist_ok=True)
items=[
('cleanup-lock-order','src/access/application.rs','        drop(active);\n        #[cfg(test)]','        #[cfg(test)]', 'access::application::tests::uncertain_cleanup_releases_execution_registry_before_closing_admission'),
('zero-packet-rights','src/adapters/supervisor/bridge.rs','    if count < 0 {\n        return Err(BridgeError);\n    }\n    // A zero-byte','    if count <= 0 {\n        return Err(BridgeError);\n    }\n    // A zero-byte','adapters::supervisor::bridge::tests::zero_length_packet_closes_every_received_descriptor'),
('required-dependency','src/adapters/supervisor/manager.rs','        property("BindsTo", vec![config.provider.clone()]),\n','', 'adapters::supervisor::manager::tests::exact_typed_manager_contract_and_no_secret_properties'),
('release-authority','src/access/application.rs',None,None,'access::direct_request_tests::final_release_revalidates_authority_after_supervisor_setup'),
('cleanup-terminal','src/access/application.rs','if report.cleanup == CleanupEvidence::Uncertain {','if false {','access::direct_request_tests::uncertain_cleanup_closes_admission_and_never_persists_terminal'),
('revocation-lifecycle','src/access/provider_store.rs','if !recovered\n','if false\n','access::direct_request_tests::running_is_observed_before_reaping_and_lock_waits_without_holding_authority'),
('recovery-before-validation','src/access/provider_store.rs','        cleanup().map_err(|_error| error(ProviderDiagnostic::PersistenceFailure))?;','        drop(cleanup);','access::provider::tests::startup_cleanup_precedes_registered_image_integrity_validation'),
('actual-helper-parent','src/adapters/supervisor/bridge.rs','libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) == 0 && libc::getppid() == parent','libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) == 0','adapters::supervisor::bridge::tests::parent_death_before_and_after_prctl_uses_actual_helper_identity'),
]
items.extend([
('queued-cancellation','src/access/application.rs','authority.provider.cancel_unclaimed_execution(owner, id)','Ok(())','access::direct_request_tests::queued_cancellation_is_owner_bound_and_prevents_later_claim'),
('unavailable-closes-admission','src/access/application.rs','if !supervisor.available() {\n            self.close_admission();','if !supervisor.available() {','access::direct_request_tests::unavailable_supervisor_prevents_claim_resolution_and_launch'),
('lease-no-replace','src/adapters/supervisor/manager.rs','std::fs::hard_link(&staging, self.lease_path(&lease.name))','std::fs::copy(&staging, self.lease_path(&lease.name))','adapters::supervisor::manager::tests::lease_publication_is_atomic_collision_safe_and_recovers_interrupted_staging'),
('recover-abandoned-staging','src/adapters/supervisor/manager.rs','if self.owns_staging(filename) {','if false {','adapters::supervisor::manager::tests::lease_publication_is_atomic_collision_safe_and_recovers_interrupted_staging'),
('discard-unrelated-jobs','src/adapters/supervisor/manager.rs','if unit == self.unit {','if true {','adapters::supervisor::manager::tests::job_observation_discards_unrelated_churn'),
('helper-name-filter','src/adapters/supervisor/manager.rs','names.insert(name.to_owned());','let _ignored_name = name;','adapters::supervisor::manager::tests::helper_environment_is_name_only_complete_and_recovery_stable'),
('worker-dispatch','src/adapters/supervisor.rs',None,None,'real:app-worker-exit'),
])
if os.environ.get('VW18_MUTANT'):
 items=[item for item in items if item[0]==os.environ['VW18_MUTANT']]
 if not items: raise RuntimeError('unknown mutant selector')
def command_for(test):
 return (['env','VW18_SCENARIO='+test.split(':',1)[1],'scripts/test-systemd-supervisor.sh'] if test.startswith('real:') else ['cargo','test','--offline','--locked','--lib',test,'--','--exact','--test-threads=1'])
def run(name,test,label):
 with (out/(name+'-'+label+'.log')).open('w') as log:
  try: return subprocess.run(command_for(test), stdout=log,stderr=subprocess.STDOUT,timeout=300).returncode
  except subprocess.TimeoutExpired: return 124
# Capture every named passing baseline while all source is pristine, then mutate.
baselines={}
for name,file,old,new,test in items:
 code=run(name,test,'baseline')
 if code: raise RuntimeError((name,'baseline',code))
 baselines[name]=(code,hashlib.sha256((root/file).read_bytes()).hexdigest())
 print(name,'baseline passed',flush=True)
results=(json.loads((out/'results.json').read_text()) if os.environ.get('VW18_MUTANT') and (out/'results.json').exists() else [])
results=[result for result in results if result['name'] not in {item[0] for item in items}]
for name,file,old,new,test in items:
 p=root/file; baseline=p.read_text(); base,source_hash=baselines[name]
 assert hashlib.sha256(baseline.encode()).hexdigest()==source_hash, name
 if name=='worker-dispatch':
  a=baseline.index('                    let _result = app.run_execution(')
  b=baseline.index('                    );',a)+len('                    );')
  mutated=baseline[:a]+'                    let _result = (&app, &id, &supervisor);'+baseline[b:]
 elif name=='release-authority':
  a=baseline.index('        let mut authority =',baseline.index('impl ExecutionControl for ApplicationExecution'))
  b=baseline.index('        action()',a)
  mutated=baseline[:a]+baseline[b:]
 else:
  assert baseline.count(old)==1,(name,baseline.count(old))
  mutated=baseline.replace(old,new)
 (out/(name+'.diff')).write_text(''.join(difflib.unified_diff(baseline.splitlines(True),mutated.splitlines(True),fromfile=file,tofile=file)))
 try:
  p.write_text(mutated)
  result=run(name,test,'mutant')
 finally: p.write_text(baseline)
 log=(out/(name+'-mutant.log')).read_text()
 classification='caught' if result==101 and 'test result: FAILED' in log else 'survived' if result==0 else 'timeout' if result==124 else 'compiler-or-infrastructure'
 results.append(dict(name=name,file=file,test=test,baseline_exit=base,mutant_exit=result,classification=classification,baseline_sha256=hashlib.sha256(baseline.encode()).hexdigest()))
 (out/'results.json').write_text(json.dumps(results,indent=2)+'\n')
 print(name,classification,flush=True)
 if classification!='caught': raise RuntimeError((name,classification))
