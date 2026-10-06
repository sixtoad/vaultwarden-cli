import difflib,hashlib,json,os,pathlib,re,signal,subprocess,time
OUT=pathlib.Path('/tmp/vw-story31-review-mutations'); SRC=OUT/'source'; TARGET=OUT/'target'
ROOT=pathlib.Path('/home/sixtocantolla/sessions/day-to-day/vaultwarden-bind-ssh-key-fixed-operation')
ENV=os.environ.copy(); ENV.update(CARGO_TARGET_DIR=str(TARGET),CARGO_BUILD_JOBS='2',RUST_TEST_THREADS='4',CARGO_NET_OFFLINE='true',VW_UI_DEPS='/tmp/vw-story21-ui/node_modules',CERTUTIL='/tmp/vw-story21-nss/extracted/usr/bin/certutil',FIREFOX='/usr/bin/firefox')
def write(path,value): path.write_text(json.dumps(value,indent=2)+'\n')
def manifest(root):
    paths=[p for folder in ('src','tests','scripts','packaging') for p in (root/folder).rglob('*') if p.is_file()]+[root/'Cargo.toml',root/'Cargo.lock']
    return {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)}
original=manifest(SRC); assert original==manifest(ROOT)
write(OUT/'baseline-source-hashes.json',original);write(OUT/'environment.json',{k:ENV[k] for k in ('CARGO_TARGET_DIR','CARGO_BUILD_JOBS','RUST_TEST_THREADS','CARGO_NET_OFFLINE','VW_UI_DEPS','CERTUTIL','FIREFOX')})
write(OUT/'isolation.json',{'source':str(SRC),'target':str(TARGET),'root':str(ROOT),'seed':'rsync -a excluding incremental, own package artifacts and fingerprints; no hardlinks','shared_target_used':False})
results=[]
def command(directory,name,args,timeout=900):
    before=manifest(SRC); write(directory/(name+'-source-hashes.json'),before)
    start=time.monotonic()
    with (directory/(name+'.log')).open('w') as log:
        p=subprocess.Popen(args,cwd=SRC,env=ENV,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
        try: code=p.wait(timeout=timeout)
        except subprocess.TimeoutExpired: os.killpg(p.pid,signal.SIGKILL);p.wait();code=124
    content=(directory/(name+'.log')).read_text(errors='replace')
    result={'name':name,'command':args,'cwd':str(SRC),'exit':code,'seconds':round(time.monotonic()-start,2),'source_unchanged':manifest(SRC)==before}
    write(directory/(name+'-result.json'),result);assert result['source_unchanged'];print(json.dumps(result),flush=True)
    return code,content
secure=['./scripts/with-secure-test-tmpdir.sh']; test='adapters::vaultwarden::tests::ssh_backend_rejects_each_ineligible_http_metadata_response'
unit=secure+['cargo','test','--lib',test,'--offline','--locked','--','--exact']
browser=secure+['node','tests/ui/direct-request.mjs']
compile_lib=['cargo','test','--lib','--no-run','--offline','--locked']
baseline=OUT/'baseline';baseline.mkdir()
for name,cmd in [('build-fixture',compile_lib),('build-cli',['cargo','build','--bin','vw-access','--offline','--locked']),('http-negative',unit),('browser',browser)]:
    code,log=command(baseline,name,cmd);assert code==0,(name,log[-2000:])
plan=[
 {'name':'http-forwarding-all-true','file':'src/adapters/vaultwarden.rs','old':'eligible_ssh_metadata(&Self::body(response)?, immutable_item_id)','new':'eligible_ssh_metadata(&Self::body(response)?, immutable_item_id).map(|_| true)','kind':'unit','expected':test},
 {'name':'ssh-pending-promises-execution','file':'src/access/policy.rs','old':'            one_time: if self.ssh.is_some() {\n                super::direct_request::PREVIOUS_ONE_TIME','new':'            one_time: if self.ssh.is_some() {\n                super::direct_request::ONE_TIME','kind':'browser','expected':'One-time meaning'},
 {'name':'ssh-approved-promises-execution','file':'src/adapters/loopback_ui.rs','old':"value.ssh?'; approved once; SSH execution is unavailable':'; approved once; awaiting protected execution'",'new':"value.ssh?'; approved once; awaiting protected execution':'; approved once; awaiting protected execution'",'kind':'browser','expected':'Request status: approved; approved once; SSH execution is unavailable'},
]
write(OUT/'plan.json',plan)
for case in plan:
    assert manifest(SRC)==original
    folder=OUT/case['name'];folder.mkdir(); file=SRC/case['file'];source=file.read_text();assert source.count(case['old'])==1
    mutant=source.replace(case['old'],case['new']);file.write_text(mutant)
    (folder/'mutation.diff').write_text(''.join(difflib.unified_diff(source.splitlines(True),mutant.splitlines(True),fromfile='a/'+case['file'],tofile='b/'+case['file'])))
    write(folder/'mutated-source-hashes.json',manifest(SRC)); print('START '+case['name'],flush=True)
    try:
        if case['kind']=='browser':
            code,log=command(folder,'build-fixture',compile_lib);assert code==0,log[-2000:]
        code,log=command(folder,'test',unit if case['kind']=='unit' else browser)
        if case['kind']=='unit':
            killed=code==101 and 'test '+test+' ... FAILED' in log and 'assertion `left == right` failed: /id' in log
            proof='named HTTP negative test fails at isolated /id response: Ok(true) vs Ok(false)'
        elif case['name']=='ssh-pending-promises-execution':
            killed=code==1 and 'AssertionError' in log and 'One-time meaning' in log and 'Approval authorizes one protected execution' in log
            proof='exact One-time meaning browser assertion reports ordinary execution promise'
        else:
            lines=(SRC/'tests/ui/direct-request.mjs').read_text().splitlines();line=next(i+1 for i,s in enumerate(lines) if "waitForFunction(()=>document.querySelector('#review-status').textContent==='"+case['expected']+"')" in s)
            killed=code==1 and 'TimeoutError: Waiting failed' in log and f'direct-request.mjs:{line}:' in log
            proof={'browser_assertion_line':line,'condition':lines[line-1],'stack_matches_condition':killed}
        result={'name':case['name'],'exit':code,'classification':'killed' if killed else ('survived' if code==0 else 'unexpected-failure'),'expected':case['expected'],'proof':proof}
        results.append(result);write(folder/'classification.json',result);write(OUT/'results.json',results);print(json.dumps(result),flush=True)
        assert killed,log[-6000:]
    finally:
        file.write_text(source); restored=manifest(SRC);write(folder/'restored-source-hashes.json',restored);assert restored==original
write(OUT/'final-restored-source-hashes.json',manifest(SRC));write(OUT/'summary.json',{'mutants':3,'killed':3,'survivors':0,'unexpected_failures':0,'baseline_passed':True,'source_restored':manifest(SRC)==original,'isolated_target':str(TARGET)})
print('COMPLETE: 3 killed; exact source restoration verified; root and shared target never mutated.',flush=True)
