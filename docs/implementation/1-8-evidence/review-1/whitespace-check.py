import json,pathlib,subprocess
root=pathlib.Path.cwd();out=root/'docs/implementation/1-8-evidence/review-1'; normalized=[]
for p in sorted((root/'docs/implementation/1-8-evidence').rglob('*')):
 if not p.is_file() or p.is_symlink():continue
 data=p.read_bytes()
 if b'\0' in data:continue
 try:data.decode('utf-8')
 except UnicodeDecodeError:continue
 updated=data
 while updated.endswith(b'\n\n'):updated=updated[:-1]
 if updated!=data:
  p.write_bytes(updated);normalized.append(str(p.relative_to(root)))
(out/'whitespace-normalization.json').write_text(json.dumps({'normalization':'remove excess blank lines at EOF only; no test result or source content changes','files':normalized},indent=2)+'\n')
for name in ['diff-check.log','added-file-whitespace.log','whitespace-results.json']:
 p=out/name
 if not p.exists():p.write_text('')
baseline='ffd8ed4c434f585b2bcb37b0ca9a8517538be662'
tracked=subprocess.run(['git','diff','--check',baseline],capture_output=True,text=True)
(out/'diff-check.log').write_text(tracked.stdout+tracked.stderr)
added=set(subprocess.check_output(['git','diff','--name-only','--diff-filter=A',baseline],text=True).splitlines())
added.update(subprocess.check_output(['git','ls-files','--others','--exclude-standard'],text=True).splitlines())
violations=[]
for path in sorted(added):
 if not (root/path).is_file():continue
 check=subprocess.run(['git','diff','--no-index','--check','/dev/null',path],capture_output=True,text=True)
 message=check.stdout+check.stderr
 if message or check.returncode not in [0,1]:violations.append({'path':path,'exit':check.returncode,'output':message})
(out/'added-file-whitespace.log').write_text(''.join(v['output'] for v in violations))
result={'baseline':baseline,'tracked_baseline_diff_exit':tracked.returncode,'new_files_checked':len(added),'normalized_evidence_files':len(normalized),'violations':violations}
(out/'whitespace-results.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result))
raise SystemExit(0 if tracked.returncode==0 and not violations else 1)
