// Actual production browser UI. No fetch replacement, fake provider, TLS bypass,
// screenshots, tracing, password logging or captured request bodies.
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import crypto from 'node:crypto';
import net from 'node:net';
import {spawn, execFileSync} from 'node:child_process';
import {pathToFileURL} from 'node:url';
import {observeHumanUnlock, armHumanDecision, observeHumanDecision, observeHumanTerminal, observeRequestPending, browserFailure} from './protected-rehearsal-human.mjs';
const [root, mode] = process.argv.slice(2);
const human = mode === '--human';
const visible = human || mode === '--human-check';
const home = path.join(root, 'private');
const profile = path.join(home, 'profile');
const deps = process.env.VW_REHEARSAL_UI_DEPS;
const metadata = JSON.parse(fs.readFileSync(path.join(deps, 'puppeteer-core/package.json')));
const {default: puppeteer} = await import(pathToFileURL(path.join(deps, 'puppeteer-core', metadata.main)));
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const bounded = async (fn, milliseconds = 30000) => {
  let timer;
  try { return await Promise.race([fn(), new Promise((_, reject) => {timer = setTimeout(() => reject(Error('deadline')), milliseconds);})]); }
  finally { clearTimeout(timer); }
};
const env = {...process.env, HOME: home, XDG_CURRENT_DESKTOP: 'X-Generic'};
let browser, xserver, display, current, guide, syntheticPassword;
let gate = 'startup';
const quiet = {env, stdio: 'ignore', timeout: 10000};
const assert = value => {if (!value) throw Error('gate');};
async function xSetup(display, cookie) {
  const name = Buffer.from(cookie ? 'MIT-MAGIC-COOKIE-1' : '');
  const data = Buffer.from(cookie || '', 'hex');
  const padded = length => (length + 3) & ~3;
  const packet = Buffer.alloc(12 + padded(name.length) + padded(data.length));
  packet[0] = 0x6c; packet.writeUInt16LE(11, 2);
  packet.writeUInt16LE(name.length, 6); packet.writeUInt16LE(data.length, 8);
  name.copy(packet, 12); data.copy(packet, 12 + padded(name.length));
  const socket = net.createConnection(`/tmp/.X11-unix/X${display.slice(1)}`);
  try {
    return await bounded(() => new Promise((resolve, reject) => {
      socket.once('connect', () => socket.write(packet));
      socket.once('data', bytes => resolve(bytes[0]));
      socket.once('error', reject);
      socket.once('end', () => reject(Error('X setup closed')));
    }), 5000);
  } finally { socket.destroy(); }
}
async function start() {
  if (visible) {
    gate = 'approved-wayland-transport';
    assert(/^\/run\/user\/\d+\/wayland-[A-Za-z0-9-]+$/.test(env.WAYLAND_DISPLAY));
    assert(env.MOZ_ENABLE_WAYLAND === '1' && env.GDK_BACKEND === 'wayland');
    assert(!env.DISPLAY && !env.XAUTHORITY);
    // An absolute socket path reuses only the compositor transport. The
    // XDG runtime, private session bus and profile remain rehearsal-owned.
    display = env.WAYLAND_DISPLAY;
    env.XDG_SESSION_TYPE = 'wayland';
  } else {
    env.XAUTHORITY = path.join(home, 'Xauthority');
    gate = 'private-xauthority';
    fs.writeFileSync(env.XAUTHORITY, '', {mode: 0o600, flag: 'wx'});
    const cookie = crypto.randomBytes(16).toString('hex');
    // The cookie stays in this process and a private file, never argv or output.
    const installAuthority = target => {
      execFileSync('/usr/bin/xauth', ['-f', env.XAUTHORITY, 'source', '-'], {...quiet, stdio: ['pipe', 'ignore', 'ignore'], input: `add ${target} MIT-MAGIC-COOKIE-1 ${cookie}\n`});
      const listing = execFileSync('/usr/bin/xauth', ['-f', env.XAUTHORITY, 'list', target], {...quiet, stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 4096}).toString();
      assert(listing.trim().length > 0 && listing.trim().split(/\s+/).at(-1) === cookie);
    };
    installAuthority(':999');
    gate = 'private-xserver';
    xserver = spawn(process.env.VW_REHEARSAL_XVFB, ['-displayfd', '3', '-screen', '0', '1024x768x24', '-nolisten', 'tcp', '-auth', env.XAUTHORITY], {env, stdio: ['ignore', 'ignore', 'ignore', 'pipe']});
    display = await bounded(() => new Promise((resolve, reject) => {
      let output = ''; xserver.stdio[3].on('data', data => {output += data; if (output.includes('\n')) resolve(`:${Number(output.trim())}`);});
      xserver.once('error', reject); xserver.once('exit', () => reject(Error('display exited')));
    }));
    assert(/^:\d+$/.test(display)); env.DISPLAY = display;
    installAuthority(display);
    assert(await xSetup(display, cookie) === 1);
    assert(await xSetup(display) === 0);
  }
  gate = 'private-browser-trust';
  const certutil = process.env.VW_REHEARSAL_CERTUTIL;
  execFileSync(certutil, ['-N', '--empty-password', '-d', `sql:${profile}`], quiet);
  execFileSync(certutil, ['-A', '-n', 'Disposable rehearsal CA', '-t', 'C,,', '-i', path.join(home, 'tls/ca.pem'), '-d', `sql:${profile}`], quiet);
  // --no-remote would disable the real desktop handoff. The explicit private
  // profile and D-Bus address isolate Firefox's remote-opening transport even
  // when the human-approved compositor transport is shared.
  gate = 'private-firefox';
  browser = await puppeteer.launch({browser: 'firefox', executablePath: process.env.VW_REHEARSAL_FIREFOX,
    userDataDir: profile, headless: false, acceptInsecureCerts: false,
    ignoreDefaultArgs: ['--no-remote'], env, dumpio: false});
  // xdg-open's generic desktop parser does not unquote Exec words. Reject
  // whitespace/metacharacters in these owned paths instead of a shell wrapper.
  for (const value of [process.env.VW_REHEARSAL_FIREFOX, profile]) assert(/^\/[A-Za-z0-9_./-]+$/.test(value));
  fs.writeFileSync(path.join(home, '.local/share/applications/rehearsal.desktop'),
    `[Desktop Entry]\nType=Application\nName=Disposable rehearsal browser\nExec=${process.env.VW_REHEARSAL_FIREFOX} --profile ${profile} --new-tab %f\nTerminal=false\nMimeType=text/html;\n`, {mode: 0o600, flag: 'wx'});
  fs.writeFileSync(path.join(home, '.config/mimeapps.list'), '[Default Applications]\ntext/html=rehearsal.desktop;\ntext/plain=rehearsal.desktop;\n', {mode: 0o600, flag: 'wx'});
  const probe = path.join(home, 'desktop-probe.html');
  fs.writeFileSync(probe, '<!doctype html><title>Disposable desktop probe</title>', {mode: 0o600, flag: 'wx'});
  gate = 'real-xdg-open';
  try {execFileSync('/usr/bin/xdg-open', [probe], {...quiet, timeout: 2000});}
  catch {throw Error('desktop rejected');}
  gate = 'firefox-desktop-handoff';
  await bounded(async () => {while (!(await browser.pages()).some(page => page.url() === pathToFileURL(probe).href)) await sleep(50);});
  return {display, authenticatedXSetup: !visible, unauthenticatedXRejected: !visible};
}
async function showGuide(step) {
  gate = 'human-guide';
  assert(human && guide && syntheticPassword);
  const instructions = {
    unlock: `Unlock the disposable provider in its other tab. Enter this synthetic-only password by hand:\n${syntheticPassword}\nThen click Unlock. Do not use an existing account or password.`,
    deny: 'The next request tab will open automatically. Verify Disposable restricted agent and rehearsal.invalid, then click Deny request. No password or provider unlock is needed for denial.',
    wrong: 'The next request tab will open automatically. Click Authenticate and approve once and enter by hand:\ndeliberately-wrong-synthetic-password\nClick Approve once. Wait for Decision rejected while the request stays pending. Then click Deny request. Do not unlock the provider again.',
    approve: `The next request tab will open automatically. Verify Disposable restricted agent and rehearsal.invalid. Click Authenticate and approve once and enter by hand:\n${syntheticPassword}\nClick the Approve once button once. Do not unlock the provider again. One later request deliberately injects a wrong synthetic field and must fail.`,
  };
  assert(Object.hasOwn(instructions, step));
  await guide.$eval('#instructions', (node, text) => {node.textContent = text;}, instructions[step]);
  await guide.bringToFront();
}
async function findReview(id) {
  return bounded(async () => {
    for (;;) {
      for (const page of await browser.pages()) {
        if (await page.$eval('#review', (_node, expected) => sessionStorage.getItem('vw_request') === expected, id).catch(() => false)) return page;
      }
      await sleep(50);
    }
  });
}
async function handle(message) {
  if (message.action === 'start') return start();
  if (message.action === 'guide') {
    gate = 'human-guide';
    assert(human && !guide && typeof message.password === 'string');
    syntheticPassword = message.password;
    guide = await browser.newPage();
    await guide.setContent('<!doctype html><title>Disposable rehearsal — operator guide</title><meta charset="utf-8"><h1>Disposable protected workflow rehearsal</h1><p>This is a new isolated Firefox profile. Only synthetic credentials belong here. Do not enter any real password. Switch between this guide and the disposable provider/request tabs. Unlock the provider only for the first step; all later passwords belong in the request approval form. Locking or unlocking again invalidates pending work. If a request expires or its session becomes unavailable, stop interacting: the runner will fail and clean up. Do not create a retry.</p><p>Each manual step waits at most five minutes; the five-minute request and fifteen-minute provider-session expiries may end the run sooner. Closing this browser or interrupting the runner fails the run and cleans up. No screenshots, recordings or entered passwords are captured.</p><pre id="instructions" style="white-space:pre-wrap;font:20px sans-serif"></pre>');
    return {};
  }
  if (message.action === 'prepare-decision') {
    assert(human);
    await guide.$eval('#instructions', node => {node.textContent = 'Wait here while the next request opens. Do not act on the request until this guide displays the next manual instruction.';});
    await guide.bringToFront();
    return {};
  }
  if (message.action === 'unlock') {
    gate = 'provider-open';
    current = await browser.newPage();
    await current.goto(pathToFileURL(path.join(home, 'state/open-vaultwarden-access.html')).href);
    await current.click('a');
    await current.waitForSelector('#password', {visible: true});
    if (human) {
      assert(!Object.hasOwn(message, 'password'));
      await showGuide('unlock');
      gate = 'provider-unlock';
      await observeHumanUnlock(current);
    } else {
      gate = 'provider-unlock';
      await current.type('#password', message.password); await current.click('#unlock button');
      await current.waitForFunction(() => document.querySelector('#result')?.textContent.includes('Provider unlocked'));
    }
    assert(await current.$eval('#password', node => node.value === ''));
    return {};
  }
  if (message.action === 'decision') {
    gate = 'request-find';
    current = await findReview(message.id);
    gate = 'request-pending';
    if (!human) await observeRequestPending(current);
    gate = 'request-details';
    await current.waitForFunction(() => document.querySelector('#details')?.childElementCount > 0 || document.querySelector('#review-status')?.textContent === 'Request status unavailable for this browser session.');
    assert(await current.$eval('#details', node => node.textContent.includes('Disposable restricted agent') && node.textContent.includes('rehearsal.invalid')));
    assert(await current.$$eval('#unlock,#password,#lock', nodes => nodes.length === 0));
    if (human) {
      assert(!Object.hasOwn(message, 'password'));
      await observeRequestPending(current);
      await armHumanDecision(current);
      gate = 'human-guide';
      await showGuide(message.decision);
      gate = 'human-decision';
      await observeHumanDecision(current, message.decision);
    } else if (message.decision === 'deny') {
      gate = 'request-submit';
      await current.click('#deny');
    } else {
      gate = 'request-submit';
      await current.click('#begin-approval');
      await current.type('#approval-password', message.decision === 'wrong' ? 'deliberately-wrong-synthetic-password' : message.password);
      await current.click('#approve');
      if (message.decision === 'wrong') {
        await current.waitForFunction(() => document.querySelector('#decision-feedback')?.textContent.includes('Decision rejected') && document.querySelector('#deny')?.disabled === false);
        assert(await current.$eval('#review-status', node => node.textContent === 'Request status: pending'));
        await current.click('#deny');
      }
    }
    gate = 'request-terminal';
    await current.waitForFunction(() => /^Request status: (completed|denied|failed|expired|invalidated)(?:;|$)/.test(document.querySelector('#review-status')?.textContent) || document.querySelector('#review-status')?.textContent === 'Request status unavailable for this browser session.');
    assert(await current.$eval('#review-status', (node, decision) => decision === 'approve' ? /^Request status: (completed|failed)(?:;|$)/.test(node.textContent) : /^Request status: denied(?:;|$)/.test(node.textContent), message.decision));
    assert(await current.$eval('#approval-password', node => node.value === ''));
    return {};
  }
  if (message.action === 'replay') {
    gate = 'request-replay';
    assert(current);
    if (human) {
      await observeHumanTerminal(current);
      return {};
    }
    // Valid authentication isolates one-time rejection from empty-password rejection.
    const status = await current.evaluate(async ({id, password}) => (await fetch('/approve', {
      method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': sessionStorage.getItem('vw_request_proof')},
      body: JSON.stringify({request_id: id, password}),
    })).status, {id: message.id, password: message.password});
    assert(status === 403);
    await current.click('#refresh');
    await current.waitForFunction(() => /Request status: (completed|denied|failed)/.test(document.querySelector('#review-status')?.textContent));
    assert(await current.$$eval('#approve,#deny', nodes => nodes.every(node => node.disabled)));
    return {};
  }
  throw Error('unknown action');
}
try {
  for await (const line of readline.createInterface({input: process.stdin, crlfDelay: Infinity})) {
    try {
      gate = 'protocol';
      const result = await bounded(() => handle(JSON.parse(line)), mode === '--human' ? 330000 : 60000);
      process.stdout.write(`${JSON.stringify({ok: true, ...result})}\n`);
    } catch {process.stdout.write(`${JSON.stringify(browserFailure(gate))}\n`); break;}
  }
} finally {
  if (browser) await bounded(() => browser.close(), 10000).catch(() => {});
  if (xserver && xserver.exitCode === null) {xserver.kill('SIGTERM'); await bounded(() => new Promise(resolve => xserver.once('exit', resolve)), 5000).catch(() => {});}
}
