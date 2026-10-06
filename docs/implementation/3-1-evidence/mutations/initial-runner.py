from pathlib import Path
import difflib,hashlib,json,os,re,signal,subprocess,sys,time
OUT=Path('/tmp/vw-story31-mutations');ROOT=OUT/'source';BASE=OUT/'baseline-source'
P='src/access/policy.rs';B='src/adapters/vaultwarden.rs';A='src/access/application.rs';PORT='src/access/ports.rs';PROV='src/access/provider.rs';UI='src/adapters/loopback_ui.rs'
plan=[]
def replace(name,file,old,new,command='ssh',count=1):
 s=(BASE/file).read_text();assert s.count(old)==count,(name,s.count(old));plan.append(dict(name=name,file=file,old=old,new=new,command=command,count=count))
def scoped(name,file,start,end,old,new,command='ssh'):
 s=(BASE/file).read_text();a=s.index(start);b=s.index(end,a);part=s[a:b];assert part.count(old)==1,(name,part.count(old));replace(name,file,part,part.replace(old,new),command)
replace('policy-immutable-uuid',P,'&& valid_item_id(&ssh.credential.item_id)','&& true')
replace('policy-explicit-ssh-use',P,'&& ssh.credential.use_type == CredentialUse::Ssh','&& true')
replace('backend-exact-uuid',B,'item.id == expected_id && item.kind == 5','true && item.kind == 5')
replace('backend-actual-type-five',B,'item.kind == 5','true')
replace('backend-undeleted',B,'item.deleted.is_none()','true')
replace('backend-required-ssh-body',B,'ssh: SshBodyShape,','ssh: serde::de::IgnoredAny,')
replace('backend-nonempty-key-field',B,'if value.is_empty() || !value.bytes().all(|b| b.is_ascii_graphic())','if !value.bytes().all(|b| b.is_ascii_graphic())')
replace('backend-duplicate-members',B,'serde_json::from_slice(bytes).map_err(|_error| SessionError::BackendUnavailable)?','serde_json::from_value(serde_json::from_slice::<serde_json::Value>(bytes).map_err(|_| SessionError::BackendUnavailable)?).map_err(|_error| SessionError::BackendUnavailable)?')
scoped('backend-default-deny',PORT,'pub trait SecretBackend:', '    fn eligible(', 'Ok(false)','Ok(true)','backend-default')
scoped('verifier-default-deny',PORT,'pub trait LoginEligibilityVerifier', '    /// Return', 'Ok(false)','Ok(true)')
replace('no-generic-targets',P,'&& draft.targets.is_empty()','&& true')
replace('no-generic-schemas',P,'&& draft.arguments.is_empty()','&& true')
replace('no-mixed-credentials',P,'&& draft.credentials.is_empty()','&& true')
replace('working-directory-validation',P,'    valid_ssh_path(working_directory)\n','    true\n')
replace('resource-path-validation',P,'&& valid_ssh_path(&destination.resource_path)','&& true')
replace('host-validation',P,'&& normalize_host(&destination.host).is_some()','&& true')
replace('explicit-nonzero-port',P,'&& destination.port != 0','&& true')
s=(BASE/P).read_text();a=s.index('        && !destination.user.is_empty()');b=s.index('        && normalize_fingerprint',a)
replace('user-validation',P,s[a:b],'        && true\n')
replace('absolute-unambiguous-path',P,'(value == "/" || valid_image_path(value))','(!value.is_empty())')
a=s.index("        || host.split('.').all(|part|");b=s.index("        || !host.split('.').all(|label|",a)
replace('numeric-host-ambiguity',P,s[a:b],'')
replace('fingerprint-sha256-prefix',P,'let encoded = value.strip_prefix("SHA256:")?;','let encoded = value.split_once(\':\')?.1;')
replace('fingerprint-exact-32-bytes',P,'(bytes.len() == 32).then','true.then')
scoped('fingerprint-base64-decoding',P,'fn normalize_fingerprint','fn valid_ssh_path','        .ok()?;','        .unwrap_or(vec![0; 32]);')
replace('ssh-request-arguments',P,'            return values.is_empty();','            return true;')
replace('ssh-unknown-authority-members',P,'#[serde(deny_unknown_fields)]\npub struct SshOperation','pub struct SshOperation')
# Each projection mutant erases exactly one serialized authority member.
for field in ['id','image','item_id','use_type','working_directory']:
 start=s.index('        struct SshProjection');end=s.index('        return hex_digest(',start);part=s[start:end]
 line=next(x for x in part.splitlines() if x.strip().startswith(field+':'))
 replace('digest-omit-'+field,P,part,part.replace(line,'            #[serde(skip_serializing)]\n'+line))
for kind,typ,fields in [('destination','SshDestination',['host','port','user','resource_path','host_fingerprint']),('image','ResolvedImage',['image_id','execution_root','path','sha256','profile'])]:
 for omitted in fields:
  fn='omit_'+kind+'_'+omitted
  projection=s[s.index('        struct SshProjection'):s.index('        return hex_digest(',s.index('        struct SshProjection'))]
  line=next(x for x in projection.splitlines() if x.strip().startswith(kind+':'))
  custom=f'''        fn {fn}<S: serde::Serializer>(value: &&{typ}, serializer: S) -> Result<S::Ok, S::Error> {{
            use serde::ser::SerializeStruct;
            let mut state = serializer.serialize_struct("{typ}", {len(fields)-1})?;
'''+''.join(f'            state.serialize_field("{f}", &value.{f})?;\n' for f in fields if f!=omitted)+'''            state.end()
        }
'''
  replace('digest-omit-'+kind+'-'+omitted,P,projection,projection.replace(line,'            #[serde(serialize_with = "'+fn+'")]\n'+line)+custom)
replace('review-fixed-target',P,'.map(|ssh| ssh.review().target())','.map(|_| "No target argument".into())')
replace('review-credential-label',P,'label: ssh.credential.label.clone(),','label: "".into(),')
replace('review-credential-use',P,'use_type: ssh.credential.use_type,','use_type: CredentialUse::Login,',count=2) # must scope separately below
plan.pop();scoped('review-credential-use',P,'    pub(crate) fn direct_review','    pub(crate) fn validate_integrity','use_type: ssh.credential.use_type,','use_type: CredentialUse::Login,')
replace('review-working-directory',P,'working_directory: self.working_directory.clone(),','working_directory: "/".into(),')
replace('review-host-pin',P,'destination: self.destination.clone(),','destination: SshDestination { host_fingerprint: format!("SHA256:{}", "A".repeat(43)), ..self.destination.clone() },')
# baseline uses zero pin; erase pin must differ from baseline to expose projection assertions
plan[-1]['new']='destination: SshDestination { host_fingerprint: format!("SHA256:{}", STANDARD_NO_PAD.encode([1;32])), ..self.destination.clone() },'
replace('activation-eligibility',PROV,'            && !verifier\n','            && false && !verifier\n')
scoped('approval-eligibility',A,'            if let Some(ssh) = policy.ssh()','            let marker =','if !eligible.unwrap_or(false)','if false && !eligible.unwrap_or(false)')
replace('ssh-execution-entrypoint-guard',A,'if candidate.1.ssh().is_some()','if false && candidate.1.ssh().is_some()')
# Actual JS rendering, tested by trusted Firefox fixture.
replace('ui-host-pin',UI,"['Pinned host fingerprint',ssh.destination.host_fingerprint]","['Pinned host fingerprint','omitted']",'browser')
replace('ui-working-directory',UI,"['Working directory',ssh.working_directory]","['Working directory','omitted']",'browser')
replace('ui-credential-use',UI,"c.label+' ('+c.use_type+')'","c.label",'browser',count=2)
(OUT/'plan.json').write_text(json.dumps(plan,indent=2)+'\n')
ENV=os.environ.copy();ENV.update(CARGO_TARGET_DIR='/home/sixtocantolla/sessions/day-to-day/vaultwarden-cli/target',CARGO_BUILD_JOBS='2',RUST_TEST_THREADS='4',CARGO_NET_OFFLINE='true',VW_UI_DEPS='/tmp/vw-story21-ui/node_modules',CERTUTIL='/tmp/vw-story21-nss/extracted/usr/bin/certutil',FIREFOX='/usr/bin/firefox')
COMMANDS={'ssh':['./scripts/with-secure-test-tmpdir.sh','cargo','test','--offline','--locked','--lib','ssh_'],'backend-default':['./scripts/with-secure-test-tmpdir.sh','cargo','test','--offline','--locked','--test','provider_session','unsupported_session_backend_denies_ssh_metadata_without_resolving'],'browser':['./scripts/with-secure-test-tmpdir.sh','node','tests/ui/direct-request.mjs']}
def manifest():
 names=json.loads((OUT/'original-source-hashes.json').read_text());return {n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in names}
def run(name,command,timeout=600):
 directory=OUT/name;directory.mkdir(exist_ok=True);(directory/'command.json').write_text(json.dumps(command)+'\n');(directory/'source-hashes.json').write_text(json.dumps(manifest(),indent=2)+'\n')
 start=time.monotonic();print('START '+name,flush=True)
 with (directory/'run.log').open('w') as log:
  child=subprocess.Popen(command,cwd=ROOT,env=ENV,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
  try: code=child.wait(timeout=timeout)
  except subprocess.TimeoutExpired: os.killpg(child.pid,signal.SIGKILL);child.wait();code=124
 output=(directory/'run.log').read_text(errors='replace')
 classification='survived' if code==0 else 'timeout' if code==124 else 'unviable' if re.search(r'error\[E\d+\]|error: could not compile',output) else 'killed' if ('test result: FAILED' in output or 'AssertionError' in output or 'assertion' in output) else 'infrastructure-failure'
 result=dict(name=name,command=command,exit=code,seconds=round(time.monotonic()-start,2),classification=classification,suites=re.findall(r'test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;',output))
 (directory/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result),flush=True);return result
if __name__=='__main__':
 phase=sys.argv[1] if len(sys.argv)>1 else 'initial';results=[];original=manifest();assert original==json.loads((OUT/'original-source-hashes.json').read_text())
 try:
  if phase=='initial':
   for key in ['ssh','backend-default','browser']:
    result=run('baseline-'+key,COMMANDS[key],900);result['classification']='baseline-pass' if result['exit']==0 else result['classification'];results.append(result)
    assert result['exit']==0,result
  selected=plan if phase=='initial' else [m for m in plan if m['name'] in sys.argv[2:]]
  for mutant in selected:
   assert manifest()==original,'copy not restored'
   name=mutant['name'];file=ROOT/mutant['file'];before=file.read_text();after=before.replace(mutant['old'],mutant['new']);assert before!=after
   directory=OUT/(name if phase=='initial' else phase+'-'+name);directory.mkdir(exist_ok=False)
   (directory/'change.diff').write_text(''.join(difflib.unified_diff(before.splitlines(True),after.splitlines(True),fromfile='a/'+mutant['file'],tofile='b/'+mutant['file'])))
   file.write_text(after)
   try: result=run(directory.name,COMMANDS[mutant['command']],900 if mutant['command']=='browser' else 600);results.append(result)
   finally: file.write_text(before);assert manifest()==original;(directory/'restored-source-hashes.json').write_text(json.dumps(manifest(),indent=2)+'\n')
   (OUT/(phase+'-results.json')).write_text(json.dumps(results,indent=2)+'\n')
 finally:
  assert manifest()==original,'RESTORATION FAILED'
  (OUT/(phase+'-final-source-hashes.json')).write_text(json.dumps(manifest(),indent=2)+'\n')
