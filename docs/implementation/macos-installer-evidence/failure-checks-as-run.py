import pathlib,subprocess,hashlib,json,os
root=pathlib.Path('/tmp/companion-installer.TZ9sC4g9'); script=root/'scripts/package-macos-companion.sh'
output=root/'output'; image=next(output.glob('*.dmg')); name=image.name
results=[]
def invoke(label,directory,environment=None):
 with (root/(label+'.log')).open('w') as log:
  result=subprocess.run(['/bin/bash',str(script),str(directory)],stdout=log,stderr=subprocess.STDOUT,env=environment,timeout=120)
 assert result.returncode!=0,label
 assert not list(directory.glob('.companion-package.*')),label
 results.append({'case':label,'exit_code':result.returncode,'staging_removed':True})
before={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in output.iterdir()}
invoke('existing-output',output)
assert before=={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in output.iterdir()}
results[-1]['existing_pair_unchanged']=True
symlinks=root/'symlink-output'; symlinks.mkdir(); target=symlinks/(name+'.sha256'); target.symlink_to('absent-target')
invoke('existing-dangling-symlink',symlinks)
assert target.is_symlink() and os.readlink(target)=='absent-target' and not (symlinks/name).exists()
results[-1]['existing_symlink_preserved']=True
shims=root/'fault-tools'; shims.mkdir()
(shims/'ln').write_text('''#!/bin/bash
set -eu
if [[ "$COMPANION_PACKAGING_FAULT" == no_links && "$1" == */link-test-source ]]; then
  echo "Injected unsupported hard links" >&2
  exit 1
fi
if [[ "$COMPANION_PACKAGING_FAULT" == checksum_race && "$1" == -h && "$2" == *.sha256 ]]; then
  printf '%s\\n' 'competing-checksum-preserve' > "$3/$(basename "$2")"
  exit 1
fi
exec /bin/ln "$@"
''')
(shims/'swift').write_text('''#!/bin/bash
printf called > "$COMPANION_BUILD_MARKER"
exec /usr/bin/swift "$@"
''')
for file in shims.iterdir(): file.chmod(0o700)
env=dict(os.environ,PATH=str(shims)+':'+os.environ['PATH'],COMPANION_BUILD_MARKER=str(root/'unexpected-build-marker'))
unsupported=root/'unsupported-output'; unsupported.mkdir()
env['COMPANION_PACKAGING_FAULT']='no_links'; invoke('unsupported-hardlinks',unsupported,env)
assert not (root/'unexpected-build-marker').exists() and not list(unsupported.iterdir())
results[-1]['rejected_before_build']=True
race=root/'race-output'; race.mkdir(); env['COMPANION_PACKAGING_FAULT']='checksum_race'; invoke('partial-publication-race',race,env)
assert not (race/name).exists()
assert (race/(name+'.sha256')).read_text()=='competing-checksum-preserve\n'
results[-1].update(own_partial_image_removed=True,competing_checksum_preserved=True)
(root/'failure-tests.json').write_text(json.dumps(results,indent=2)+'\n')
print(json.dumps(results,indent=2))
