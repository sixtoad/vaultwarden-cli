import subprocess,re,os,json,hashlib,pathlib
repo=pathlib.Path.cwd();out=repo/'docs/implementation/1-8-evidence/review-2-parent'
def command(args):return subprocess.check_output(args,text=True,timeout=20)
lines=command(['systemctl','--user','list-units','--all','--plain','--no-legend','vw18-*','vw-access-*']).splitlines()
names=[line.split()[0] for line in lines if line.strip()]
props=command(['systemctl','--user','show',*names,'-p','Id','-p','ExecStart','-p','BindsTo','-p','PartOf','-p','ActiveState','-p','ControlGroup','-p','Transient'])
units={}
for block in props.strip().split('\n\n'):
 data=dict(line.split('=',1) for line in block.splitlines() if '=' in line)
 if data.get('Id'):units[data['Id']]=data
harness={name:data for name,data in units.items() if name.startswith(('vw18-harness-','vw18-panic-')) and str(repo/'target/debug/deps/vaultwarden_cli-') in data.get('ExecStart','') and 'adapters::supervisor::real_tests::provider_harness' in data.get('ExecStart','') and data.get('Transient')=='yes' and data.get('ActiveState') in ['inactive','failed']}
requests={}
for name,data in units.items():
 provider=data.get('BindsTo','')
 if provider not in harness or data.get('PartOf')!=provider or data.get('Transient')!='yes' or data.get('ActiveState') not in ['inactive','failed']:continue
 prefix='vw-access-'+hashlib.sha256(f'{os.geteuid()}:{provider}'.encode()).hexdigest()[:16]+'-'
 if re.fullmatch(re.escape(prefix)+r'[0-9a-f]{32}\.service',name) and '/.vaultwarden-cli-tests.' in data.get('ExecStart','') and '/helper ' in data.get('ExecStart',''):requests[name]=data
plan={'harnesses':harness,'requests':requests,'preserved':[name for name in names if name not in harness and name not in requests]}
(out/'cleanup-plan.json').write_text(json.dumps(plan,indent=2)+'\n')
print(json.dumps({'verified_harnesses':len(harness),'verified_requests':len(requests),'preserved':len(plan['preserved']),'active_selected':False}))
print('preserved unit names:',plan['preserved'])
