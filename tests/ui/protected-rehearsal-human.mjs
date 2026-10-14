// Human mode is an observer, not an input driver. Keep these methods separate
// so tests can supply read-only pages with no click/type/evaluate capability.
const assert = value => { if (!value) throw Error('human observation rejected'); };
// Only these fixed stage names may cross the browser-driver boundary. Never
// derive diagnostics from exceptions, URLs, page text or request contents.
export function browserFailure(stage) {
  const stages = ['startup', 'approved-wayland-transport', 'private-xauthority',
    'private-xserver', 'private-browser-trust', 'private-firefox', 'real-xdg-open',
    'firefox-desktop-handoff', 'human-guide', 'provider-open', 'provider-unlock',
    'request-find', 'request-pending', 'request-details', 'human-decision',
    'request-submit', 'request-terminal', 'request-replay', 'protocol'];
  return {ok: false, gate: stages.includes(stage) ? stage : 'unspecified'};
}
export async function observeRequestPending(page, timeout = 30000) {
  await page.waitForFunction(() => {
    const status = document.querySelector('#review-status')?.textContent;
    return status === 'Request status: pending'
      || /^Request status: (completed|denied|failed|expired|invalidated)(?:;|$)/.test(status)
      || status === 'Request status unavailable for this browser session.';
  }, {timeout});
  assert(await page.$eval('#review-status', node => node.textContent === 'Request status: pending'));
}
export async function observeHumanUnlock(page, timeout = 300000) {
  await page.waitForFunction(() => document.querySelector('#result')?.textContent.includes('Provider unlocked'), {timeout});
  assert(await page.$eval('#password', node => node.value === ''));
}
// Arm before the guide invites any manual action. Keep only booleans: no input
// values, DOM snapshots, URLs, request bodies, or exception text are retained.
export async function armHumanDecision(page) {
  await page.evaluate(() => {
    if (window.rehearsalDecision) throw Error('observer already armed');
    const state = {rejectedPending: false, denied: false, completed: false, failed: false, invalid: false};
    window.rehearsalDecision = state;
    const sample = () => {
      const status = document.querySelector('#review-status')?.textContent;
      state.rejectedPending ||= status === 'Request status: pending'
        && document.querySelector('#decision-feedback')?.textContent.includes('Decision rejected') === true;
      state.denied ||= /^Request status: denied(?:;|$)/.test(status);
      state.completed ||= /^Request status: completed(?:;|$)/.test(status);
      state.failed ||= /^Request status: failed(?:;|$)/.test(status);
      state.invalid ||= /^Request status: (expired|invalidated)(?:;|$)/.test(status)
        || status === 'Request status unavailable for this browser session.';
    };
    new MutationObserver(sample).observe(document.querySelector('#review'), {subtree: true, childList: true, characterData: true});
    sample();
  });
}
export async function observeHumanDecision(page, decision, timeout = 300000) {
  assert(['deny', 'wrong', 'approve'].includes(decision));
  await page.waitForFunction(() => {
    const state = window.rehearsalDecision;
    return state && (state.denied || state.completed || state.failed || state.invalid);
  }, {timeout});
  assert(await page.evaluate(expected => {
    const state = window.rehearsalDecision;
    return state && !state.invalid && (expected === 'approve'
      ? (state.completed || state.failed) && !state.denied
      : state.denied && !state.completed && !state.failed && (expected !== 'wrong' || state.rejectedPending));
  }, decision));
  assert(await page.$eval('#review-status', (node, expected) => expected === 'approve'
    ? /^Request status: (completed|failed)(?:;|$)/.test(node.textContent)
    : /^Request status: denied(?:;|$)/.test(node.textContent), decision));
  assert(await page.$eval('#approval-password', node => node.value === ''));
}
export async function observeHumanTerminal(page) {
  // Do not emit a new approval request in human mode. Automated mode separately
  // tests an actual rejected HTTP replay. Here observe the terminal UI only.
  assert(await page.$$eval('#approve,#deny', nodes => nodes.length === 2 && nodes.every(node => node.disabled)));
}
