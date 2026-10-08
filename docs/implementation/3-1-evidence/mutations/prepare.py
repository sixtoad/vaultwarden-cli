from pathlib import Path
import shutil,json,hashlib
src=Path('/home/sixtocantolla/sessions/day-to-day/vaultwarden-bind-ssh-key-fixed-operation');out=Path('/tmp/vw-story31-mutations');dst=out/'source'
assert not dst.exists()
shutil.copytree(src,dst,ignore=shutil.ignore_patterns('.git','target','node_modules'))
names=[p.relative_to(dst).as_posix() for p in dst.rglob('*') if p.is_file() and (p.relative_to(dst).parts[0] in ('src','tests','scripts','packaging') or p.name in ('Cargo.toml','Cargo.lock'))]
manifest={name:hashlib.sha256((dst/name).read_bytes()).hexdigest() for name in sorted(names)}
(out/'original-source-hashes.json').write_text(json.dumps(manifest,indent=2)+'\n')
shutil.copytree(dst,out/'baseline-source')
