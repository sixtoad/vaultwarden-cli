#!/usr/bin/env python3
"""Semantic management-core mutations. Compilation is never a kill."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
root = Path(__file__).resolve().parents[1]
source = root / 'companion/rust/src/provider/management.rs'
original = source.read_bytes()
output = Path(sys.argv[1]).resolve()
output.mkdir(parents=True, exist_ok=True)
mutations = {
    'action-fact-matrix': ('|| !valid_action_facts(&r.revocation, &r.cleanup)', '|| false'),
    'late-read': ('if flight.epoch != self.epoch && !action {', 'if false && flight.epoch != self.epoch && !action {'),
    'exact-target': ('!= target\n                {', '!= target && false\n                {'),
    'status-only': ('if self.recovery.is_some() && command != ManagementCommand::Status {', 'if false && self.recovery.is_some() && command != ManagementCommand::Status {'),
    'action-binding': ('|| r.action_id != expected.action_id', '|| false && r.action_id != expected.action_id'),
    'ticket-expiry': ('t.started.elapsed() < Duration::from_secs(t.prepared.valid_for_seconds.into())', 'true'),
    'read-only-origin-binding': ('r.request_id != f.target.id', 'false'),
}
report = {'original_sha256':hashlib.sha256(original).hexdigest(), 'mutations':{}}
def run(name, compile_only=False):
    cmd=['cargo','test','--locked','--offline','--manifest-path',str(root/'companion/rust/Cargo.toml')]
    if compile_only: cmd.append('--no-run')
    with (output/f'{name}.log').open('wb') as log:
        return subprocess.run(cmd,cwd=root,stdout=log,stderr=subprocess.STDOUT,timeout=180).returncode
try:
    if run('baseline'): raise RuntimeError('baseline failed')
    for name,(old,new) in mutations.items():
        if original.decode().count(old)!=1: raise RuntimeError(f'{name}: mutation anchor drift')
        source.write_text(original.decode().replace(old,new))
        if run(f'{name}-compile',True): raise RuntimeError(f'{name}: compile failure is not a kill')
        code=run(name)
        caught=code!=0 and 'test result: FAILED' in (output/f'{name}.log').read_text()
        report['mutations'][name]={'caught':caught,'exit_code':code}
        source.write_bytes(original)
        if not caught: raise RuntimeError(f'{name}: survived')
finally:
    source.write_bytes(original)
    report['restored_sha256']=hashlib.sha256(source.read_bytes()).hexdigest()
    report['restored_exit']=run('restored')
    (output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
if report['restored_exit']: raise SystemExit('restored baseline failed')
