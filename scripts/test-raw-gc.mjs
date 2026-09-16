import assert from 'node:assert/strict';
import test from 'node:test';

import { isSessionRetentionElapsed, verifyShadowParity } from '../src/raw-gc.mjs';

function fakeRuntime(sequence) {
  let index = 0;
  let counters = { pending: 0, compared: 0, matched: 0, mismatched: 0, unavailable: 0, inconclusive: 0, skipped: 0 };
  const calls = [];
  return {
    reader: {
      get: async args => {
        calls.push(args);
        const step = sequence[index]; index += 1;
        counters = { ...counters, ...step.countersAfter };
      }
    },
    status: () => ({ mode: 'shadow', ...counters }),
    calls
  };
}

test('verifyShadowParity: a clean single comparison (compared+1, no errors) proves parity', async () => {
  const runtime = fakeRuntime([{ countersAfter: { pending: 0, compared: 1, matched: 1 } }]);
  const result = await verifyShadowParity({ runtime, sessionId: 'ses_a', sleep: async () => {} });
  assert.deepEqual(result, { ok: true, mismatchCount: 0 });
  assert.deepEqual(runtime.calls, [{ id: 'ses_a' }]);
});

test('verifyShadowParity: a mismatch in the delta fails verification', async () => {
  const runtime = fakeRuntime([{ countersAfter: { pending: 0, compared: 1, mismatched: 1 } }]);
  const result = await verifyShadowParity({ runtime, sessionId: 'ses_a', sleep: async () => {} });
  assert.equal(result.ok, false);
  assert.equal(result.mismatchCount, 1);
});

test('verifyShadowParity: inconclusive or unavailable also fail verification', async () => {
  const inconclusive = fakeRuntime([{ countersAfter: { pending: 0, compared: 1, inconclusive: 1 } }]);
  assert.equal((await verifyShadowParity({ runtime: inconclusive, sessionId: 'ses_a', sleep: async () => {} })).ok, false);
  const unavailable = fakeRuntime([{ countersAfter: { pending: 0, compared: 0, unavailable: 1 } }]);
  assert.equal((await verifyShadowParity({ runtime: unavailable, sessionId: 'ses_a', sleep: async () => {} })).ok, false);
});

test('verifyShadowParity: no reader (disabled runtime) is never verified', async () => {
  assert.deepEqual(await verifyShadowParity({ runtime: null, sessionId: 'ses_a' }), { ok: false, mismatchCount: null });
  assert.deepEqual(await verifyShadowParity({ runtime: { reader: null, status: () => ({ mode: 'shadow' }) }, sessionId: 'ses_a' }), { ok: false, mismatchCount: null });
});

test('verifyShadowParity: waits (polls) until the scheduled comparison drains before reading the delta', async () => {
  const counters = { pending: 0, compared: 0, matched: 0, mismatched: 0, unavailable: 0, inconclusive: 0, skipped: 0 };
  let polls = 0;
  const runtime = {
    reader: { get: async () => { counters.pending = 1; } },
    status: () => ({ mode: 'shadow', ...counters })
  };
  const sleep = async () => {
    polls += 1;
    if (polls === 2) { counters.pending = 0; counters.compared = 1; counters.matched = 1; }
  };
  const result = await verifyShadowParity({ runtime, sessionId: 'ses_a', pendingPollIntervalMs: 1, sleep });
  assert.equal(result.ok, true);
  assert.equal(polls, 2);
});

test('isSessionRetentionElapsed: default 3-year policy, no scope override', () => {
  const session = { firstOccurredAt: '2020-01-01T00:00:00.000Z' };
  assert.equal(isSessionRetentionElapsed(session, '2026-07-12T12:00:00.000Z', {}, null), true);
  assert.equal(isSessionRetentionElapsed(session, '2021-01-01T00:00:00.000Z', {}, null), false);
});

test('isSessionRetentionElapsed: an explicit scope override shortens the window', () => {
  const session = { firstOccurredAt: '2026-01-01T00:00:00.000Z' };
  const policy = { scopeDays: { 'person:test': 10 } };
  assert.equal(isSessionRetentionElapsed(session, '2026-01-15T00:00:00.000Z', policy, 'person:test'), true);
  assert.equal(isSessionRetentionElapsed(session, '2026-01-05T00:00:00.000Z', policy, 'person:test'), false);
});
