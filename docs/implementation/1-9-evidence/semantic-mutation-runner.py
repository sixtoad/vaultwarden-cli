import difflib, hashlib, json, os, pathlib, subprocess, time
root=pathlib.Path.cwd(); out=root/'docs/implementation/1-9-evidence'/os.environ.get('STORY19_MUTATION_PHASE','semantic'); out.mkdir(parents=True,exist_ok=True)
lib=['cargo','test','--offline','--locked','--lib']
def case(name,path,old,new,test): return dict(name=name,path=path,old=old,new=new,command=lib+[test,'--','--exact','--test-threads=1'])
cases=[]
h='src/access/history.rs'; a='src/access/application.rs'; p='src/access/provider.rs'; d='src/access/direct_request.rs'; s='src/access/provider_store.rs'
ht='access::history_tests::'
def add(name,path,old,new,test): cases.append(case(name,path,old,new,ht+test))
add('requester-attribution',h,'uid: record.owner_uid,','uid: record.owner_uid + 1,','history_submission_and_decision_have_exact_allowlisted_snapshots')
add('policy-projection',h,'policy_revision: record.review.policy_digest.clone(),','policy_revision: record.review.arguments_digest.clone(),','history_submission_and_decision_have_exact_allowlisted_snapshots')
add('credential-projection',h,'credentials: record.review.credentials.clone(),','credentials: Vec::new(),','history_submission_and_decision_have_exact_allowlisted_snapshots')
add('application-human-check',a,'self.check_owner(owner)?;\n        self.history_current(None, limit)','let _ = owner;\n        self.history_current(None, limit)','history_owner_and_browser_generation_guards_work_while_locked')
add('provider-human-check',p,'if owner.uid() != self.owner_uid() {','if false && owner.uid() != self.owner_uid() {','history_provider_owner_guard_is_independent_of_application_authentication')
add('browser-generation',a,'if generation.is_some_and(|g| g != authority.generation) {','if false && generation.is_some_and(|g| g != authority.generation) {','history_owner_and_browser_generation_guards_work_while_locked')
add('minimum-limit',h,'(1..=MAX_HISTORY_LIMIT).contains(&limit)','(0..=MAX_HISTORY_LIMIT).contains(&limit)','history_limits_empty_equal_timestamps_and_all_tiebreakers_are_deterministic')
add('maximum-limit',h,'(1..=MAX_HISTORY_LIMIT).contains(&limit)','(1..=201).contains(&limit)','history_limits_empty_equal_timestamps_and_all_tiebreakers_are_deterministic')
add('default-limit',h,'DEFAULT_HISTORY_LIMIT: u32 = 50','DEFAULT_HISTORY_LIMIT: u32 = 49','history_default_and_maximum_limits_count_events')
add('timestamp-precedence',h,'(b.at_unix_seconds, &b.request_id, b.ordinal).cmp(&(\n            a.at_unix_seconds,','(None::<u64>, &b.request_id, b.ordinal).cmp(&(\n            None::<u64>,','history_time_precedes_identity_and_ordinal_and_unknown_time_sorts_last')
add('identity-tiebreak',h,'(b.at_unix_seconds, &b.request_id, b.ordinal)','(b.at_unix_seconds, &a.request_id, b.ordinal)','history_time_precedes_identity_and_ordinal_and_unknown_time_sorts_last')
add('ordinal-tiebreak',h,'(b.at_unix_seconds, &b.request_id, b.ordinal)','(b.at_unix_seconds, &b.request_id, a.ordinal)','history_time_precedes_identity_and_ordinal_and_unknown_time_sorts_last')
add('bounded-query',h,'    events.truncate(limit);','    let _ = limit;','history_default_and_maximum_limits_count_events')
add('legacy-binding',d,'if event.binding != record.approval_binding() {','if false && event.binding != record.approval_binding() {','history_malformed_storage_unknown_versions_duplicates_and_state_mismatch_fail_closed')
add('final-lifecycle-consistency',d,'previous.as_ref() == Some(&self.review.status)','true','history_malformed_storage_unknown_versions_duplicates_and_state_mismatch_fail_closed')
add('execution-claim-consistency',d,'if !self.execution_claimed\n                && matches!(','if false && !self.execution_claimed\n                && matches!(','history_recorded_execution_requires_a_claim_independently_of_other_guards')
add('recovery-invalidation',s,'self.invalidate(true)','self.invalidate(false)','history_terminal_restart_is_idempotent_and_pending_never_regains_authority')
add('durable-submission',p,'self.store.write_state(&state)?;\n        self.state = state;\n        Ok(review)','self.state = state;\n        Ok(review)','history_submission_and_decision_have_exact_allowlisted_snapshots')
add('transition-event',s,'direct.audit.push(super::history::HistoryEvent::snapshot(\n            direct,\n            direct.audit.len() as u32,\n            now,\n            super::history::outcome(&next, outcome),\n            Some(next.clone()),\n        ));','let _ = (now, outcome);','history_every_lifecycle_projection_has_exact_fields_and_distinct_outcomes')
cli=case('terminal-controls','src/bin/vw-access.rs','if character.is_control()','if false', 'unused')
cli['command']=['cargo','test','--offline','--locked','--bin','vw-access','tests::history_arguments_and_terminal_json_preserve_data_without_controls','--','--exact','--test-threads=1']
cases.append(cli)
ui='src/adapters/loopback_ui.rs'
source=(root/ui).read_text()
visible=next(line for line in source.splitlines() if line.startswith('function visibleText(value)'))
for name,old,new in [('browser-control-escaping',visible,'function visibleText(value){return String(value);}'),('browser-html-escaping','description.textContent=visibleText(value);','description.innerHTML=visibleText(value);')]:
 item=case(name,ui,old,new,'unused');item['command']=['node','tests/ui/direct-request.mjs'];cases.append(item)

# Review regressions: each mutation reaches an independently observed boundary.
item=case('history-record-owner',p,'.filter_map(|r| r.direct)\n                .filter(|d| d.owner_uid == owner.uid())','.filter_map(|r| r.direct)','access::direct_request_tests::correctly_sealed_other_owner_record_is_not_disclosed_to_current_human');cases.append(item)
add('history-first-expiry',a,'super::history::limit(limit)?;\n        self.expire_requests(&mut authority)?;','super::history::limit(limit)?;','history_first_read_at_request_deadline_expires_pending_and_approved_once')
add('legacy-execution-phase',d,'DirectStatus::Approved => DirectStatus::Running,','DirectStatus::Approved => return Err("invalid legacy history"),','history_completed_legacy_three_approvals_reconstruct_exact_phases_and_restart_stably')
for name,old,new in [
 ('history-pending-mutation','if(historyLoading||retired||pendingMutations)return;','if(historyLoading||retired)return;'),
 ('history-session-retirement','function retireSession(){retired=true;resetHistory();','function retireSession(){retired=true;'),
 ('history-review-independence','\nvoid loadHistory();\nif(requestId)','\nawait loadHistory();\nif(requestId)')]:
 item=case(name,ui,old,new,'unused');item['command']=['node','tests/ui/direct-request.mjs'];cases.append(item)

selected=os.environ.get('STORY19_MUTANT_FILTER')
if selected is not None:
 names=[name.strip() for name in selected.split(',')]
 known={item['name'] for item in cases}
 if any(not name or name not in known for name in names):
  raise SystemExit('STORY19_MUTANT_FILTER must contain nonempty, known mutant names.')
 cases=[item for item in cases if item['name'] in names]
# Source restoration is unconditional. A compile error or timeout never counts as caught.
env=os.environ.copy(); env['RUST_TEST_THREADS']='1'; env['CARGO_NET_OFFLINE']='true'; env['VW_UI_DEPS']='/tmp/vw-story14-browser/node_modules'; env['CERTUTIL']='/tmp/vw-story13-nss/extracted/usr/bin/certutil'
results=[]
def run(item,kind):
 start=time.monotonic()
 with (out/(item['name']+'-'+kind+'.log')).open('w') as log:
  try: code=subprocess.run(item['command'],stdout=log,stderr=subprocess.STDOUT,env=env,timeout=240).returncode
  except subprocess.TimeoutExpired: code=124
 return code,round(time.monotonic()-start,2)
for item in cases:
 path=root/item['path']; original=path.read_text(); assert original.count(item['old'])==1,(item['name'],original.count(item['old']))
 baseline,seconds=run(item,'baseline'); assert baseline==0,(item['name'],'baseline',baseline)
 mutant=original.replace(item['old'],item['new'])
 (out/(item['name']+'.diff')).write_text(''.join(difflib.unified_diff(original.splitlines(True),mutant.splitlines(True),fromfile=item['path'],tofile=item['path'])))
 try:
  path.write_text(mutant); code,duration=run(item,'mutant')
 finally: path.write_text(original)
 text=(out/(item['name']+'-mutant.log')).read_text()
 classification='caught' if ((code==101 and 'test result: FAILED' in text) or (code==1 and ('AssertionError' in text or ('TimeoutError: Waiting failed: 30000ms exceeded' in text and 'waitForFunction' in text)))) else 'survived' if code==0 else 'infrastructure-or-unviable'
 result=dict(name=item['name'],path=item['path'],command=item['command'],baseline_exit=baseline,baseline_seconds=seconds,mutant_exit=code,mutant_seconds=duration,classification=classification,source_sha256=hashlib.sha256(original.encode()).hexdigest())
 results.append(result); (out/'results.json').write_text(json.dumps(results,indent=2)+'\n'); print(json.dumps(result),flush=True)
 assert path.read_text()==original
print('Semantic campaign finished; all sources restored.',flush=True)
