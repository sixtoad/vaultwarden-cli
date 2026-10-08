#!/usr/bin/env python3
"""Scoped semantic guard mutations; restores exact source bytes even on failure.
Run only while no other process edits/builds this worktree.
"""
import hashlib
import json
import pathlib
import subprocess
import time

root = pathlib.Path(__file__).resolve().parents[3]
out = pathlib.Path(__file__).resolve().parent
cases = [
    ('password-verification', 'src/access/direct_request.rs', '        authenticator\n            .authenticate(password)\n            .map_err(|_error| DirectRequestError::AuthenticationFailed)?;', '        drop(password);'),
    ('mutual-tls', 'src/adapters/companion.rs', '.with_client_cert_verifier(identity::verifier(client_ca)?)', '.with_no_client_auth()'),
    ('core-generation', 'src/access/application.rs', 'authority.generation != generation', 'false'),
    ('core-exact-review', 'src/access/application.rs', 'authority.provider.direct_review(self.owner, id)? != *review', 'false'),
    ('core-final-ticket-deadline', 'src/access/application.rs', 'prepared\n                .companion_deadline\n                .is_none_or(|deadline| self.clock.now() < deadline)', 'true'),
    ('ticket-device', 'src/adapters/companion.rs', 't.device == device && t.review.id == request && t.token == token', 't.review.id == request && t.token == token'),
    ('ticket-consumption', 'src/adapters/companion.rs', 'Some(self.tickets.swap_remove(position))', 'Some(Ticket { token: self.tickets[position].token.clone(), device: self.tickets[position].device.clone(), review: self.tickets[position].review.clone(), generation: self.tickets[position].generation, deadline: self.tickets[position].deadline })'),
    ('password-rate-limit', 'src/adapters/companion.rs', 'attempts.len() >= 5', 'false'),
    ('enrollment-leaf', 'src/adapters/companion.rs', 'entries.iter().any(|entry| entry.fingerprint == device)', '!entries.is_empty()'),
    ('unknown-json-fields', 'src/adapters/companion.rs', '#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]', '#[serde(tag = "command", rename_all = "snake_case")]'),
    ('identity-file-permissions', 'src/adapters/companion_identity.rs', 'meta.mode() & 0o7777 != 0o600', 'false'),
]
results = []
for name, filename, original, replacement in cases:
    path = root / filename
    before = path.read_bytes()
    source = before.decode()
    record = {'name': name, 'file': filename, 'sha256': hashlib.sha256(before).hexdigest()}
    if source.count(original) != 1:
        record.update(outcome='skipped', reason='expected exact source match was absent or nonunique')
        results.append(record)
        continue
    started = time.monotonic()
    try:
        path.write_text(source.replace(original, replacement, 1))
        with (out / (name + '.log')).open('w') as log:
            result = subprocess.run(['./scripts/with-secure-test-tmpdir.sh', 'cargo', 'test', '--offline', '--locked', '--lib', 'companion'], cwd=root, stdout=log, stderr=subprocess.STDOUT, timeout=240)
        log = (out / (name + '.log')).read_text()
        record.update(exit_code=result.returncode, outcome=('survived' if result.returncode == 0 else 'killed' if 'test result: FAILED' in log else 'invalid'))
    except subprocess.TimeoutExpired:
        record.update(outcome='timeout')
    finally:
        path.write_bytes(before)
        assert hashlib.sha256(path.read_bytes()).hexdigest() == record['sha256']
    record['elapsed_seconds'] = round(time.monotonic() - started, 2)
    results.append(record)
    (out / 'security-mutations.json').write_text(json.dumps(results, indent=2) + '\n')
(out / 'security-mutations.json').write_text(json.dumps(results, indent=2) + '\n')
print(json.dumps(results, indent=2))
