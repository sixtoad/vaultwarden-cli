from pathlib import Path
import difflib,json
import runner
OUT=runner.OUT;ROOT=runner.ROOT
fixed=runner.manifest();assert fixed==json.loads((OUT/'post-fix-source-hashes.json').read_text())
original=json.loads((OUT/'initial-results.json').read_text())+json.loads((OUT/'extra-results.json').read_text());survivors=[r['name'] for r in original if r['classification']=='survived'];results=[]
try:
 baseline=runner.run('post-fix-baseline-ssh',runner.COMMANDS['ssh']);baseline['classification']='baseline-pass' if baseline['exit']==0 else baseline['classification'];(OUT/'post-fix-baseline-ssh'/'result.json').write_text(json.dumps(baseline,indent=2)+'\n');results.append(baseline)
 assert baseline['exit']==0,baseline
 baseline=runner.run('post-fix-baseline-browser',runner.COMMANDS['browser'],900);baseline['classification']='baseline-pass' if baseline['exit']==0 else baseline['classification'];(OUT/'post-fix-baseline-browser'/'result.json').write_text(json.dumps(baseline,indent=2)+'\n');results.append(baseline)
 assert baseline['exit']==0,baseline
 for name in survivors:
  assert runner.manifest()==fixed,'not restored to post-fix baseline'
  mutant=next(m for m in runner.plan if m['name']==name);file=ROOT/mutant['file'];before=file.read_text();assert before.count(mutant['old'])==mutant['count'];after=before.replace(mutant['old'],mutant['new']);assert after!=before
  directory=OUT/('fixed-'+name);directory.mkdir(exist_ok=False);(directory/'change.diff').write_text(''.join(difflib.unified_diff(before.splitlines(True),after.splitlines(True),fromfile='a/'+mutant['file'],tofile='b/'+mutant['file'])))
  file.write_text(after)
  try: results.append(runner.run(directory.name,runner.COMMANDS[mutant['command']]))
  finally: file.write_text(before);assert runner.manifest()==fixed;(directory/'restored-source-hashes.json').write_text(json.dumps(fixed,indent=2)+'\n')
  (OUT/'post-fix-results.json').write_text(json.dumps(results,indent=2)+'\n')
finally:
 assert runner.manifest()==fixed
 (OUT/'post-fix-final-source-hashes.json').write_text(json.dumps(fixed,indent=2)+'\n')
