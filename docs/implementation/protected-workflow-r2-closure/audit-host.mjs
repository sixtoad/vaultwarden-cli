// Independent read-only absence audit, executed after the final rehearsal.
import fs from 'node:fs';
import os from 'node:os';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
const uid = process.getuid();
const run = (program, args) => execFileSync(program, args, {encoding: 'utf8', timeout: 10000, stdio: ['ignore', 'pipe', 'pipe']}).trim();
const absent = file => {
  try { fs.lstatSync(file); assert.fail('owned resource remains'); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
};
assert.equal(run('/usr/bin/systemctl', ['--user', 'show', 'vaultwarden-accessd.service', '--property=LoadState', '--value']), 'not-found');
assert.equal(run('/usr/bin/systemctl', ['--user', 'show', 'vaultwarden-accessd.service', '--property=ActiveState', '--value']), 'inactive');
assert.equal(run('/usr/bin/systemctl', ['--user', 'list-units', '--all', '--plain', '--no-legend', 'vw-protected-rehearsal-*']), '');
assert.equal(run('/usr/bin/docker', ['ps', '--all', '--quiet', '--filter', 'label=vw.rehearsal']), '');
assert.equal(run('/usr/bin/find', [`/sys/fs/cgroup/user.slice/user-${uid}.slice`, '-name', '*vw-protected-rehearsal-*']), '');
assert(!fs.readdirSync(os.homedir()).some(name => name.startsWith('.vw-protected-rehearsal-')));
const namespace = crypto.createHash('sha256').update(`${uid}:vaultwarden-accessd.service`).digest('hex').slice(0, 16);
absent(`/run/user/${uid}/vw-access-${namespace}`);
for (const name of fs.readdirSync('/proc').filter(name => /^\d+$/.test(name))) {
  try {
    if (fs.statSync(`/proc/${name}`).uid !== uid) continue;
    const cmdline = fs.readFileSync(`/proc/${name}/cmdline`, 'utf8');
    assert(!cmdline.includes('tests/ui/protected-rehearsal.mjs'), 'rehearsal controller remains');
    assert(!cmdline.includes('/.vw-protected-rehearsal-'), 'owned rehearsal process remains');
  } catch (error) { if (error.code !== 'ENOENT' && error.code !== 'ESRCH') throw error; }
}
console.log('PASS: provider not-found/inactive; no rehearsal units/cgroups, labeled containers, private roots, supervisor runtime or owned controller/process.');
