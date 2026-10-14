import test from 'node:test';
import assert from 'node:assert/strict';
import {setTimeout as delay} from 'node:timers/promises';
import {observeHumanUnlock, armHumanDecision, observeHumanDecision as observeDecision, observeHumanTerminal, observeRequestPending, browserFailure} from './protected-rehearsal-human.mjs';
async function observeHumanDecision(page, decision) {
  await armHumanDecision(page);
  return observeDecision(page, decision);
}

// No click, type or request-sending methods. Evaluation installs/reads only the
// boolean DOM observer; these tests do not constitute human UI acceptance.
function readOnlyPage(frames) {
  let frame = {}, sample;
  const window = {};
  function evaluate(predicate, ...args) {
    const previous = {document: globalThis.document, window: globalThis.window, MutationObserver: globalThis.MutationObserver};
    globalThis.document = {querySelector: selector => frame[selector]};
    globalThis.window = window;
    globalThis.MutationObserver = class {constructor(callback) {sample = callback;} observe() {}};
    try {return predicate(...args);} finally {Object.assign(globalThis, previous);}
  }
  const timeouts = [];
  return {
    timeouts,
    evaluate,
    advance() {frame = frames.shift(); if (sample) evaluate(sample);},
    state: window,
    async waitForFunction(predicate, options, ...args) {
      assert(options.timeout > 0 && options.timeout <= 300000);
      timeouts.push(options.timeout);
      while (frames.length) {
        this.advance();
        if (evaluate(predicate, ...args)) return;
      }
      assert.equal(evaluate(predicate, ...args), true, 'required manual transition absent');
    },
    async $eval(selector, predicate, ...args) {return predicate(frame[selector], ...args);},
    async $$eval(_selector, predicate) {return predicate(frames[0]);},
  };
}
test('human unlock only observes actual unlocked result and cleared field', async () => {
  const page = readOnlyPage([{'#result': {textContent: 'Provider unlocked'}, '#password': {value: ''}}]);
  await observeHumanUnlock(page);
  assert.deepEqual(page.timeouts, [300000]);
});
test('instructed wrong-password step requires generic rejection while pending, then denial', async () => {
  const page = readOnlyPage([
    {'#decision-feedback': {textContent: 'Decision rejected'}, '#review-status': {textContent: 'Request status: pending'}},
    {'#review-status': {textContent: 'Request status: denied; no operation will run'}, '#approval-password': {value: ''}},
  ]);
  await observeHumanDecision(page, 'wrong');
  assert.equal(page.timeouts.length, 1);
});
test('rapid rejected-pending then denied before polling is retained as booleans only', async () => {
  const page = readOnlyPage([
    {'#decision-feedback': {textContent: 'Decision rejected'}, '#review-status': {textContent: 'Request status: pending'}},
    {'#review-status': {textContent: 'Request status: denied'}, '#approval-password': {value: ''}},
  ]);
  await armHumanDecision(page);
  page.advance(); page.advance();
  await observeDecision(page, 'wrong');
  assert(Object.values(page.state.rehearsalDecision).every(value => typeof value === 'boolean'));
  assert.equal(page.state.rehearsalDecision.rejectedPending, true);
});
test('regular human denial observes denied status and cleared field', async () => {
  await observeHumanDecision(readOnlyPage([
    {'#review-status': {textContent: 'Request status: denied; no operation will run'}, '#approval-password': {value: ''}},
  ]), 'deny');
});
test('human approval observes completed or wrong-field failed terminal status', async () => {
  for (const status of ['completed; exit code: 0', 'failed; reason: execution_nonzero']) {
    await observeHumanDecision(readOnlyPage([
      {'#review-status': {textContent: `Request status: ${status}`}, '#approval-password': {value: ''}},
    ]), 'approve');
  }
});
test('uncleared password fields reject both unlock and approval observations', async () => {
  await assert.rejects(observeHumanUnlock(readOnlyPage([
    {'#result': {textContent: 'Provider unlocked'}, '#password': {value: 'synthetic-not-cleared'}},
  ])));
  await assert.rejects(observeHumanDecision(readOnlyPage([
    {'#review-status': {textContent: 'Request status: completed'}, '#approval-password': {value: 'synthetic-not-cleared'}},
  ]), 'approve'));
});
test('denial alone does not prove the instructed rejection transition', async () => {
  const page = readOnlyPage([{'#review-status': {textContent: 'Request status: denied'}}]);
  await assert.rejects(observeHumanDecision(page, 'wrong'));
});
test('unexpected completion does not satisfy requested denial', async () => {
  const page = readOnlyPage([{'#review-status': {textContent: 'Request status: completed'}}]);
  await assert.rejects(observeHumanDecision(page, 'deny'));
});
test('expired and retired sessions reject immediately instead of awaiting another manual decision', async () => {
  for (const status of ['Request status: expired', 'Request status: invalidated', 'Request status unavailable for this browser session.']) {
    for (const decision of ['deny', 'wrong', 'approve']) {
      const page = readOnlyPage([{'#review-status': {textContent: status}}]);
      await assert.rejects(observeHumanDecision(page, decision));
      assert.equal(page.timeouts.length, 1);
    }
  }
});
test('pending observer rejects invalidated, expired and retired requests immediately', async () => {
  await observeRequestPending(readOnlyPage([{'#review-status': {textContent: 'Request status: pending'}}]));
  for (const status of ['expired', 'invalidated', 'completed; exit code: 0']) {
    const page = readOnlyPage([{'#review-status': {textContent: `Request status: ${status}`}}]);
    await assert.rejects(observeRequestPending(page));
    assert.equal(page.timeouts.length, 1);
  }
  await assert.rejects(observeRequestPending(readOnlyPage([{'#review-status': {textContent: 'Request status unavailable for this browser session.'}}])));
});
test('browser failure output permits only fixed stages, never exception or page data', () => {
  for (const stage of ['human-decision', 'provider-unlock', 'request-find', 'request-terminal']) {
    assert.deepEqual(browserFailure(stage), {ok: false, gate: stage});
  }
  for (const data of ['password-sentinel', 'https://localhost/#private-capability', Error('password-sentinel'), {gate: 'human-decision', password: 'password-sentinel'}, null]) {
    assert.deepEqual(browserFailure(data), {ok: false, gate: 'unspecified'});
  }
});
test('human timeout and closed-page failures propagate without input attempts', async () => {
  const started = Date.now();
  const page = {async waitForFunction(_predicate, {timeout}) {await delay(timeout); throw Error('deadline');}};
  await assert.rejects(observeHumanUnlock(page, 10), /deadline/);
  assert(Date.now() - started < 1000);
  await assert.rejects(observeHumanUnlock({async waitForFunction() {throw Error('page closed');}}), /page closed/);
});
test('human replay observation checks disabled controls without sending a decision', async () => {
  await observeHumanTerminal(readOnlyPage([[{disabled: true}, {disabled: true}]]));
  await assert.rejects(observeHumanTerminal(readOnlyPage([[{disabled: false}, {disabled: true}]])));
});
