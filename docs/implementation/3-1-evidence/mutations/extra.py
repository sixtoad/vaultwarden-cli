import difflib,json
import runner
OUT=runner.OUT;ROOT=runner.ROOT;original=runner.manifest();assert original==json.loads((OUT/'original-source-hashes.json').read_text())
name='ui-history-credential-use';mutant=next(m for m in runner.plan if m['name']==name);file=ROOT/mutant['file'];before=file.read_text();assert before.count(mutant['old'])==1;after=before.replace(mutant['old'],mutant['new']);directory=OUT/name;directory.mkdir(exist_ok=False);(directory/'change.diff').write_text(''.join(difflib.unified_diff(before.splitlines(True),after.splitlines(True),fromfile='a/'+mutant['file'],tofile='b/'+mutant['file'])))
file.write_text(after)
try:
 result=runner.run(name,runner.COMMANDS['browser'],900);(OUT/'extra-results.json').write_text(json.dumps([result],indent=2)+'\n')
finally:
 file.write_text(before);assert runner.manifest()==original;(directory/'restored-source-hashes.json').write_text(json.dumps(original,indent=2)+'\n');(OUT/'extra-final-source-hashes.json').write_text(json.dumps(original,indent=2)+'\n')
