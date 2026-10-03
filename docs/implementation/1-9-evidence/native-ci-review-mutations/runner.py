import difflib, hashlib, json, os, pathlib, subprocess, time
root=pathlib.Path.cwd()
out=root/'docs/implementation/1-9-evidence/native-ci-review-mutations'
out.mkdir(parents=True,exist_ok=True)
env=os.environ.copy();env['CARGO_NET_OFFLINE']='true';env['RUST_TEST_THREADS']='4'
env.setdefault('VW_UI_DEPS','/tmp/vw-story14-browser/node_modules')
env.setdefault('CERTUTIL','/tmp/vw-story13-nss/extracted/usr/bin/certutil')
commands={'cli':['cargo','test','--offline','--locked','--bin','vw-access'], 'browser':['node','tests/ui/direct-request.mjs']}
cli='src/bin/vw-access.rs';ui='src/adapters/loopback_ui.rs'
cases=[]
def add(name,path,old,new,group,scope=None): cases.append(dict(name=name,path=path,old=old,new=new,group=group,scope=scope))
add('terminal-controls',cli,'if character.is_control()','if false','cli','production')
for char in ['200b','2060','feff']:
 add('terminal-format-'+char,cli,"'\\u{"+char+"}' | ",'','cli','production')
add('terminal-newline-bound',cli,'if safe.len() >= MAX_OUTPUT','if safe.len() > MAX_OUTPUT','cli','production')
visible=next(line for line in (root/ui).read_text().splitlines() if line.startswith('function visibleText(value)'))
add('browser-control-escaping',ui,visible,'function visibleText(value){return String(value);}','browser')
add('browser-html-escaping',ui,'description.textContent=visibleText(value);','description.innerHTML=visibleText(value);','browser')
for char in ['200b','2060','feff']:
 add('browser-format-'+char,ui,visible,visible.replace('\\u'+char,''),'browser')
add('browser-selected-limit',ui,'body:JSON.stringify({limit}),signal:controller.signal','body:JSON.stringify({limit:50}),signal:controller.signal','browser')
add('browser-deadline',ui,'controller.abort();reject(Error());','/* deadline disabled */','browser')
results=[];baselines=[]
def invoke(name,command):
 start=time.monotonic()
 with (out/(name+'.log')).open('w') as log:
  try:code=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,env=env,timeout=240).returncode
  except subprocess.TimeoutExpired:code=124
 return code,round(time.monotonic()-start,2)
for group in ['cli','browser']:
 code,seconds=invoke(group+'-baseline',commands[group]);baselines.append(dict(group=group,exit=code,seconds=seconds))
 print(json.dumps(baselines[-1]),flush=True)
 assert code==0,('baseline',group,code)
 for item in [c for c in cases if c['group']==group]:
  path=root/item['path'];original=path.read_text()
  if item['scope']=='production':
   before,after=original.split('#[cfg(all(test, target_os = "linux"))]',1)
   assert before.count(item['old'])==1,item['name']
   mutated=before.replace(item['old'],item['new'])+'#[cfg(all(test, target_os = "linux"))]'+after
  else:
   assert original.count(item['old'])==1,(item['name'],original.count(item['old']))
   mutated=original.replace(item['old'],item['new'])
  assert mutated!=original,item['name']
  (out/(item['name']+'.diff')).write_text(''.join(difflib.unified_diff(original.splitlines(True),mutated.splitlines(True),fromfile=item['path'],tofile=item['path'])))
  try:
   path.write_text(mutated);code,seconds=invoke(item['name'],commands[group])
  finally:path.write_text(original)
  text=(out/(item['name']+'.log')).read_text()
  assertion=(code==101 and 'test result: FAILED' in text) or (code==1 and 'AssertionError' in text)
  deadline=code==1 and 'TimeoutError: Waiting failed: 30000ms exceeded' in text and 'waitForFunction' in text
  classification='caught' if assertion or deadline else 'survived' if code==0 else 'infrastructure-or-unviable'
  result=dict(name=item['name'],path=item['path'],command=commands[group],exit=code,seconds=seconds,classification=classification,evidence='assertion' if assertion else 'bounded browser assertion deadline' if deadline else 'unexpected result',restored_sha256=hashlib.sha256(path.read_bytes()).hexdigest())
  results.append(result)
  (out/'results.json').write_text(json.dumps(dict(baselines=baselines,mutations=results),indent=2)+'\n')
  print(json.dumps(result),flush=True)
  assert path.read_text()==original
  assert classification=='caught',(item['name'],classification)
print('All 12 scoped mutations caught; sources restored.',flush=True)
