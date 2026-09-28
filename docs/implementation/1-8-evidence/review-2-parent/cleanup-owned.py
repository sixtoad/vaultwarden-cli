import subprocess,json,pathlib,os,time,stat,hashlib
out=pathlib.Path('docs/implementation/1-8-evidence/review-2-parent');plan=json.loads((out/'cleanup-plan.json').read_text());selected={**plan['requests'],**plan['harnesses']}
def run(args,check=True):return subprocess.run(args,text=True,capture_output=True,timeout=20,check=check)
for name,data in selected.items():
 text=run(['systemctl','--user','show',name,'-p','Id','-p','ExecStart','-p','BindsTo','-p','PartOf','-p','ActiveState','-p','Transient']).stdout
 now=dict(line.split('=',1) for line in text.splitlines() if '=' in line)
 assert all(now.get(key)==data.get(key) for key in ['Id','ExecStart','BindsTo','PartOf','ActiveState','Transient']),name
run(['systemctl','--user','stop',*selected],False)
# Independent scan includes live and zombie processes, including deleted cgroups.
for entry in pathlib.Path('/proc').iterdir():
 if not entry.name.isdecimal():continue
 try:groups=(entry/'cgroup').read_text()
 except FileNotFoundError:continue
 for group in groups.splitlines():
  if group.startswith('0::'):
   components=group[3:].removesuffix(' (deleted)').split('/')
   assert not any(name in selected for name in components),'test process remains'
run(['systemctl','--user','reset-failed',*selected],False)
deadline=time.monotonic()+15
while True:
 remaining=[line.split()[0] for line in run(['systemctl','--user','list-units','--all','--plain','--no-legend',*selected]).stdout.splitlines() if line.strip()]
 if not remaining:break
 assert time.monotonic()<deadline,remaining
 time.sleep(.1)
removed=[];preserved=[]
for provider in plan['harnesses']:
 ns=hashlib.sha256(f'{os.geteuid()}:{provider}'.encode()).hexdigest()[:16]
 runtime=pathlib.Path(f'/run/user/{os.geteuid()}/vw-access-{ns}')
 if not runtime.exists():continue
 meta=runtime.lstat();assert stat.S_ISDIR(meta.st_mode) and meta.st_uid==os.geteuid() and stat.S_IMODE(meta.st_mode)==0o700
 for request,data in plan['requests'].items():
  if data['BindsTo']!=provider:continue
  nonce=request.rsplit('-',1)[1].removesuffix('.service')
  for file in [runtime/(request+'.json'),runtime/(nonce+'.sock')]:
   try:meta=file.lstat()
   except FileNotFoundError:continue
   assert meta.st_uid==os.geteuid() and stat.S_IMODE(meta.st_mode)==0o600 and (stat.S_ISREG(meta.st_mode) or stat.S_ISSOCK(meta.st_mode)),file
   file.unlink();removed.append(str(file))
 try:runtime.rmdir();removed.append(str(runtime))
 except OSError:preserved.append(str(runtime))
result={'selected_harnesses':len(plan['harnesses']),'selected_requests':len(plan['requests']),'remaining_selected_units':remaining,'process_scan':'no matching live/zombie processes','removed_artifacts':removed,'preserved_nonempty_directories':preserved,'unrelated_units_touched':False}
(out/'cleanup-result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items() if k!='removed_artifacts'}));print('removed owned artifacts/directories:',len(removed))
