import os, subprocess, sys
env=os.environ.copy(); env['RUST_TEST_THREADS']='4'; env['CARGO_NET_OFFLINE']='true';env['STORY19_MUTATION_PHASE']='review-semantic';env['STORY19_EVIDENCE_PHASE']='post-review'
commands=[
 ['python3','docs/implementation/1-9-evidence/semantic-mutation-runner.py'],
 ['cargo','mutants','--no-config','--in-place','--file','src/access/history.rs','--re',r'replace HistoryEvent::(valid|consistent_outcome|matches_record) -> bool|replace limit ->|replace newest -> Vec<HistoryEvent> with vec!\[\]|in outcome|delete match arm','--output','docs/implementation/1-9-evidence/review-generated','--timeout','120','--build-timeout','180','--','--lib','history'],
 ['python3','docs/implementation/1-9-evidence/verification-runner.py'],
 ['python3','docs/implementation/1-9-evidence/review-fix/runner-guards.py'],
 ['git','diff','--check']
]
for command in commands:
 print('START '+repr(command),flush=True)
 result=subprocess.run(command,env=env)
 if result.returncode: sys.exit(result.returncode)
print('POST-REVIEW CAMPAIGNS AND FULL VERIFICATION FINISHED',flush=True)
