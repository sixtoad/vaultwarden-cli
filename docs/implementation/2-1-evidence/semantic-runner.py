import difflib, hashlib, json, os, pathlib, signal, subprocess, time
def run_command(command, log, env, timeout):
    process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                               env=env, start_new_session=True)
    try:
        return process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        # Cargo/test descendants share this dedicated group. Kill all of them
        # before the caller restores mutated source or starts another check.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        return 124

root=pathlib.Path.cwd()
out=root/'docs/implementation/2-1-evidence'/os.environ.get('STORY21_MUTATION_PHASE','semantic')
out.mkdir(parents=True,exist_ok=True)
cases=[]
def add(name,path,old,new,test):
    cases.append(dict(name=name,path=path,old=old,new=new,command=['cargo','test','--offline','--locked','--lib',test,'--','--exact','--test-threads=1']))
b='src/access/agent_binding.rs'; a='src/access/application.rs'; p='src/access/provider.rs'; d='src/access/direct_request.rs'; s='src/access/provider_store.rs'
bt='access::agent_binding_tests::'; dt='access::direct_request_tests::'
add('weak-key','src/access.rs','if key.is_weak()','if false',bt+'key_codec_rejects_encoding_length_invalid_points_weak_and_noncanonical_points')
add('noncanonical-point','src/access.rs','key.to_edwards().compress().to_bytes() != key_bytes','false',bt+'key_codec_rejects_encoding_length_invalid_points_weak_and_noncanonical_points')
add('same-uid',b,'|| self.uid == provider_uid','|| false',bt+'pairing_rejects_each_invalid_label_and_os_identity_independently')
add('zero-os-id',b,'id != 0 && id != u32::MAX','id != u32::MAX',bt+'pairing_rejects_each_invalid_label_and_os_identity_independently')
add('reserved-os-id',b,'id != 0 && id != u32::MAX','id != 0',bt+'pairing_rejects_each_invalid_label_and_os_identity_independently')
add('fingerprint-integrity',b,'|| self.fingerprint != hex_sha256(key.as_bytes())','|| false',bt+'registry_enforces_unique_ids_keys_enabled_labels_and_immutable_audit')
add('uid-match',b,'&& self.uid == uid','&& true',bt+'os_match_requires_enabled_exact_uid_and_required_membership')
add('group-match',b,'&& groups.contains(&self.gid)','&& true',bt+'os_match_requires_enabled_exact_uid_and_required_membership')
add('enabled-status',b,'self.status == AgentBindingStatus::Enabled && self.uid == uid','true && self.uid == uid',bt+'os_match_requires_enabled_exact_uid_and_required_membership')
add('duplicate-keys',b,'|| !keys.insert(&binding.public_key)','|| { keys.insert(&binding.public_key); false }',bt+'revoked_label_needs_fresh_key_and_id_and_retains_both_audit_events')
add('duplicate-labels',b,'|| (binding.status == AgentBindingStatus::Enabled && !labels.insert(&binding.label))','|| (false && binding.status == AgentBindingStatus::Enabled && !labels.insert(&binding.label))',bt+'registry_enforces_unique_ids_keys_enabled_labels_and_immutable_audit')
add('audit-actor',b,'if event != &binding.audit(provider_uid, event.timestamp_unix_seconds, event.action) {','if false && event != &binding.audit(provider_uid, event.timestamp_unix_seconds, event.action) {',bt+'registry_enforces_unique_ids_keys_enabled_labels_and_immutable_audit')
add('legacy-schema',s,'1 if raw.pairings.is_empty() && raw.agent_audit.is_none() => Vec::new(),','1 if raw.pairings.is_empty() => Vec::new(),',bt+'schema_migration_is_narrow_closed_and_repeatable')
add('provider-admin',p,'if human.uid() != self.owner_uid() {','if false && human.uid() != self.owner_uid() {',dt+'agent_provider_administration_revalidates_human_independently_of_application')
add('binding-id-lookup',p,'.find(|b| b.id == id && b.matches_os(uid, groups))','.find(|b| b.matches_os(uid, groups))',dt+'agent_os_lookup_and_exact_poll_ownership_reject_each_independent_mismatch')
add('poll-owner',p,'.filter(|d| d.agent_owner.as_ref() == Some(owner))','.filter(|_| true)',dt+'agent_os_lookup_and_exact_poll_ownership_reject_each_independent_mismatch')
add('historical-owner-reference',s,'!self.pairings.iter().any(|binding| owner.matches(binding))','false',dt+'agent_request_seals_and_legacy_migration_cannot_rewrite_attribution')
add('scoped-invalidation',p,'&& d.agent_owner.as_ref().is_some_and(|a| a.binding_id == id)','&& d.agent_owner.is_some()',dt+'agent_revoke_invalidates_only_unclaimed_owned_work_and_preserves_attribution')
add('revocation-publication',a,'token.store(true, Ordering::Release);','token.store(false, Ordering::Release);',dt+'agent_revocation_intent_fences_backend_continuation_before_gate_is_available')
add('revocation-durable-write',p,'            self.store.write_state(&state)?;\n        }\n        self.state = state;\n        Ok(view)','            // mutation: omit revocation write\n        }\n        self.state = state;\n        Ok(view)',dt+'agent_revocation_persists_across_restart_without_rewriting_old_owners')
add('pair-durable-write',p,'        self.store.write_state(&state)?;\n        self.state = state;\n        Ok(view)','        self.state = state;\n        Ok(view)',dt+'agent_administration_checks_human_authority_even_while_locked_and_retains_tombstones')
add('revocation-failure-closure',a,'        if result.is_err() {\n            self.close_admission();\n        }\n        // A claim holds gate','        if false && result.is_err() {\n            self.close_admission();\n        }\n        // A claim holds gate',dt+'agent_pair_and_revoke_persistence_failures_close_admission_and_preserve_denial')
add('cleanup-wait',a,'        self.await_agent_cleanup(&affected)?;','        let _ = affected;',dt+'agent_running_revoke_rejects_uncertain_and_impossible_not_started_cleanup')
add('running-reaping',p,'|| (direct.review.status == DirectStatus::Running && cleanup != CleanupEvidence::Reaped)','|| false',dt+'agent_running_revoke_rejects_uncertain_and_impossible_not_started_cleanup')
add('duplicate-binding-ids',b,'by_id.insert(binding.id.as_str(), binding).is_some()','{ by_id.insert(binding.id.as_str(), binding); false }',bt+'duplicate_binding_id_is_rejected_independently_of_key_label_and_audit_checks')
add('registry-read-validation',s,'        state.validate_for_owner(self.owner_uid)?;\n        Ok(state)','        Ok(state)',bt+'durable_binding_registry_corruption_rejects_warmed_reads_and_restart_independently')
add('cleanup-timeout',a,'let uncertain = ids.iter().any(|id| active.contains_key(id))','let uncertain = false',dt+'agent_cleanup_timeout_keeps_running_nonterminal_until_confirmed_reaping')
add('pair-label-preflight',p,'|| (b.status == AgentBindingStatus::Enabled && b.label == binding.label)','|| false',dt+'agent_administration_checks_human_authority_even_while_locked_and_retains_tombstones')
add('pair-key-preflight',p,'b.public_key == binding.public_key','false',dt+'agent_administration_checks_human_authority_even_while_locked_and_retains_tombstones')
add('revoke-exact-id',p,'.find(|b| b.id == id)','.find(|_| true)',dt+'agent_revoke_targets_requested_id_when_another_binding_precedes_it')
add('running-scope',a,'.filter(|(_, execution)| execution.agent_id.as_deref() == Some(id))','.filter(|(_, execution)| execution.agent_id.is_some())',dt+'agent_running_revoke_and_retry_wait_for_confirmed_scoped_cleanup')
# Regression mutations added after workflow review.
cases.extend([{'name': 'pair-after-gate-closure',
  'path': 'src/access/application.rs',
  'old': '        if self.admission_closed() {\n'
         '            return Err(DirectRequestError::Unavailable);\n'
         '        }\n'
         '        let result = authority\n'
         '            .provider\n'
         '            .pair_agent',
  'new': '        if false {\n'
         '            return Err(DirectRequestError::Unavailable);\n'
         '        }\n'
         '        let result = authority\n'
         '            .provider\n'
         '            .pair_agent',
  'command': ['cargo',
              'test',
              '--offline',
              '--locked',
              '--lib',
              'access::application::tests::pair_agent_rechecks_closed_admission_after_waiting_for_gate',
              '--',
              '--exact',
              '--test-threads=1']},
 {'name': 'pair-before-publication-closure',
  'path': 'src/access/application.rs',
  'old': '                if self.admission_closed() {\n'
         '                    return Err(DirectRequestError::Unavailable);\n'
         '                }\n'
         '                self.agent_tokens',
  'new': '                if false {\n'
         '                    return Err(DirectRequestError::Unavailable);\n'
         '                }\n'
         '                self.agent_tokens',
  'command': ['cargo',
              'test',
              '--offline',
              '--locked',
              '--lib',
              'access::application::tests::pair_agent_rechecks_closed_admission_before_token_publication',
              '--',
              '--exact',
              '--test-threads=1']},
 {'name': 'poll-session-expiry',
  'path': 'src/access/application.rs',
  'old': '            match self.admit(&mut authority) {\n'
         '                Ok(()) | Err(SessionError::Locked) => {}\n'
         '                Err(error) => return Err(error.into()),\n'
         '            }\n'
         '            self.expire_requests(&mut authority)?;\n'
         '            authority.provider.agent_status(owner, uid, groups, id)',
  'new': '            self.expire_requests(&mut authority)?;\n'
         '            authority.provider.agent_status(owner, uid, groups, id)',
  'command': ['cargo',
              'test',
              '--offline',
              '--locked',
              '--lib',
              'access::application::tests::agent_status_refreshes_request_and_session_expiry_at_exact_deadlines',
              '--',
              '--exact',
              '--test-threads=1']},
 {'name': 'poll-request-expiry',
  'path': 'src/access/application.rs',
  'old': '            match self.admit(&mut authority) {\n'
         '                Ok(()) | Err(SessionError::Locked) => {}\n'
         '                Err(error) => return Err(error.into()),\n'
         '            }\n'
         '            self.expire_requests(&mut authority)?;\n'
         '            authority.provider.agent_status(owner, uid, groups, id)',
  'new': '            match self.admit(&mut authority) {\n'
         '                Ok(()) | Err(SessionError::Locked) => {}\n'
         '                Err(error) => return Err(error.into()),\n'
         '            }\n'
         '            authority.provider.agent_status(owner, uid, groups, id)',
  'command': ['cargo',
              'test',
              '--offline',
              '--locked',
              '--lib',
              'access::application::tests::agent_status_refreshes_request_and_session_expiry_at_exact_deadlines',
              '--',
              '--exact',
              '--test-threads=1']},
 {'name': 'cli-leading-hyphen-label',
  'path': 'src/bin/vw-access.rs',
  'old': '    Pair {\n        #[arg(allow_hyphen_values = true)]\n        label: String,',
  'new': '    Pair {\n        label: String,',
  'command': ['cargo',
              'test',
              '--offline',
              '--locked',
              '--test',
              'human_cli',
              'agent_commands_send_exact_identity_fields_and_print_only_safe_views',
              '--',
              '--exact',
              '--test-threads=1']},
 {'name': 'revoke-response-timeout',
  'path': 'src/adapters/human_socket.rs',
  'old': '    let response_timeout = if matches!(&command, HumanCommand::AgentRevoke { .. }) {\n'
         '        Duration::from_secs(30)',
  'new': '    let response_timeout = if matches!(&command, HumanCommand::AgentRevoke { .. }) {\n'
         '        Duration::from_secs(10)',
  'command': ['cargo',
              'test',
              '--offline',
              '--locked',
              '--lib',
              'adapters::human_socket::tests::agent_revoke_exchange_waits_beyond_the_ordinary_response_timeout',
              '--',
              '--exact',
              '--test-threads=1']}])
selected=os.environ.get('STORY21_MUTANT_FILTER')
if selected:
    names=selected.split(','); assert all(n in {c['name'] for c in cases} for n in names)
    cases=[c for c in cases if c['name'] in names]
env=os.environ.copy();env['RUST_TEST_THREADS']='1';env['CARGO_BUILD_JOBS']='2';env['CARGO_NET_OFFLINE']='true'
results=[]
def run(item,kind):
    start=time.monotonic(); logpath=out/(item['name']+'-'+kind+'.log')
    with logpath.open('w') as log:
        code=run_command(item['command'],log,env,600)
    return code,round(time.monotonic()-start,2),logpath.read_text()
baselines={}
originals={item['path']:(root/item['path']).read_text() for item in cases}
for item in cases:
    assert originals[item['path']].count(item['old'])==1,(item['name'],'anchor')
    print('BASELINE '+item['name'],flush=True)
    baseline,seconds,baseline_log=run(item,'baseline')
    assert baseline==0 and '1 passed;' in baseline_log,(item['name'],'baseline',baseline)
    baselines[item['name']]=(baseline,seconds)
for item in cases:
    path=root/item['path']; original=originals[item['path']]
    assert path.read_text()==original,(item['name'],'source changed')
    baseline,seconds=baselines[item['name']]
    mutant=original.replace(item['old'],item['new'])
    (out/(item['name']+'.diff')).write_text(''.join(difflib.unified_diff(original.splitlines(True),mutant.splitlines(True),fromfile=item['path'],tofile=item['path'])))
    try:
        path.write_text(mutant)
        code,duration,log=run(item,'mutant')
    finally:
        path.write_text(original)
    classification='caught' if code==101 and 'test result: FAILED' in log else 'survived' if code==0 else 'timeout' if code==124 else 'unviable-or-infrastructure'
    result=dict(name=item['name'],path=item['path'],command=item['command'],baseline_exit=baseline,baseline_seconds=seconds,mutant_exit=code,mutant_seconds=duration,classification=classification,source_sha256=hashlib.sha256(original.encode()).hexdigest())
    results.append(result);(out/'results.json').write_text(json.dumps(results,indent=2)+'\n');print(json.dumps(result),flush=True)
    assert path.read_text()==original
print('Semantic campaign finished; all mutated sources restored.',flush=True)

raise SystemExit(0 if all(result["classification"] == "caught" for result in results) else 1)
