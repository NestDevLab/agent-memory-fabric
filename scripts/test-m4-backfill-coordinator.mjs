import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

import {
  M4_BACKFILL_MAX_EVENTS,
  planM4BackfillBatch,
  runM4BackfillBatch,
} from '../src/migration/m4-backfill-coordinator.mjs';

const fixture = JSON.parse(fs.readFileSync(
  new URL('./fixtures/m4-backfill-coordinator.synthetic.json', import.meta.url),
  'utf8',
));
const signature = 'a'.repeat(43);
const digest = marker => `sha256:${Buffer.from(String(marker), 'utf8').toString('hex').padEnd(64, 'a').slice(0, 64)}`;

function gate(overrides = {}) {
  return {
    schema: 'amf.m4-backfill-gate/v1',
    state: 'approved',
    runId: 'm4-run-001',
    phase: 'v2-archive',
    pauseEvidence: { manifestId: 'pause-manifest-001', digest: digest('pause'), signature },
    rollbackEvidence: { manifestId: 'rollback-manifest-001', digest: digest('rollback'), signature },
    sourceCheckpoint: { id: 'source-checkpoint-001', digest: digest('source') },
    targetCheckpoint: { id: 'target-checkpoint-001', digest: digest('target') },
    ...overrides,
  };
}

function event(sequence) {
  return {
    eventId: `cevt_backfill${String(sequence).padStart(4, '0')}`,
    integrity: { payloadDigest: digest(`payload-${sequence}`) },
  };
}

function row(sequence, overrides = {}) {
  return {
    sequence,
    checkpoint: { id: `row-checkpoint-${sequence}`, digest: digest(`row-${sequence}`) },
    event: event(sequence),
    ...overrides,
  };
}

function acknowledgement(eventMetadata, duplicate = false) {
  return {
    eventId: eventMetadata.eventId,
    payloadDigest: eventMetadata.integrity.payloadDigest,
    state: 'acknowledged',
    duplicate,
  };
}

function progressAcknowledgement(progress) {
  return {
    schema: 'amf.m4-backfill-progress-ack/v1',
    committed: true,
    runId: progress.runId,
    phase: progress.phase,
    planDigest: progress.planDigest,
    sequence: progress.sequence,
    checkpoint: structuredClone(progress.checkpoint),
  };
}

function asyncRows(rows, close = null) {
  return {
    [Symbol.asyncIterator]() {
      let index = 0;
      return {
        async next() {
          return index < rows.length ? { value: rows[index++], done: false } : { done: true };
        },
        async return() {
          if (close) {
            close.count += 1;
            if (close.fail) throw new Error('close private detail');
          }
          return { done: true };
        },
      };
    },
  };
}

function dependencies(rows, options = {}) {
  const calls = options.calls ?? [];
  const committed = options.committed ?? [];
  const delivered = new Map();
  const outbox = options.outbox ?? {
    async enqueue(value) {
      calls.push(['enqueue', value.eventId]);
      return {
        eventId: value.eventId,
        payloadDigest: value.integrity.payloadDigest,
        state: 'pending',
        duplicate: false,
      };
    },
    async deliver(eventId, sink) {
      calls.push(['deliver', eventId, sink]);
      const metadata = { eventId, integrity: { payloadDigest: delivered.get(eventId) ?? digest(eventId) } };
      return acknowledgement(metadata, false);
    },
  };
  const originalEnqueue = outbox.enqueue.bind(outbox);
  outbox.enqueue = async value => {
    const result = await originalEnqueue(value);
    if (result?.eventId && result?.payloadDigest) delivered.set(result.eventId, result.payloadDigest);
    return result;
  };

  return {
    calls,
    committed,
    lease: {
      async acquire(input) { calls.push(['acquire', input]); },
      async heartbeat(input) { calls.push(['heartbeat', input]); },
      async release(input) {
        calls.push(['release', input]);
        if (options.releaseFailure) throw new Error('release private detail');
      },
    },
    source: {
      async open(input) {
        calls.push(['open', input]);
        options.mutateOpen?.(input);
        return options.iterable ?? asyncRows(rows, options.close);
      },
    },
    outbox,
    sink: { async deliver() {} },
    checkpointStore: {
      async load(input) { calls.push(['load', input]); return options.loaded ?? null; },
      async commit(progress) {
        calls.push(['commit', progress.sequence]);
        const expected = structuredClone(progress);
        options.mutateCommit?.(progress);
        if (options.commitFailure) throw new Error('commit private detail');
        committed.push(expected);
        return options.commitAcknowledgement?.(expected) ?? progressAcknowledgement(expected);
      },
    },
  };
}

async function confirmedRun(rows, options = {}) {
  const gateVerifier = options.gateVerifier ?? (async () => gate());
  const maxEvents = options.maxEvents ?? 2;
  const plan = await planM4BackfillBatch({ gateVerifier, maxEvents });
  const resolved = {
    ...options,
    loaded: typeof options.loaded === 'function' ? options.loaded(plan) : options.loaded,
  };
  const deps = dependencies(rows, resolved);
  const result = await runM4BackfillBatch({
    gateVerifier,
    maxEvents,
    confirmedPlanDigest: options.confirmedPlanDigest ?? plan.planDigest,
    ...deps,
  });
  return { result, deps, plan };
}

test('planning is deterministic, fixture-backed, gate-first, and mutation-free', async () => {
  let gateCalls = 0;
  const gateVerifier = async () => { gateCalls += 1; return fixture.gate; };
  const first = await planM4BackfillBatch({ gateVerifier, maxEvents: 2 });
  const second = await planM4BackfillBatch({ gateVerifier, maxEvents: 2 });
  const fixtureBatch = await confirmedRun(fixture.rows, { gateVerifier: async () => fixture.gate });

  assert.equal(fixture.schema, 'amf.m4-backfill-coordinator-fixture/v1');
  assert.match(fixture.description, /^Synthetic, content-free /);
  assert.equal(gateCalls, 2);
  assert.deepEqual(first, second);
  assert.match(first.planDigest, /^sha256:[a-f0-9]{64}$/);
  assert.equal(fixtureBatch.result.complete, true);
  assert.doesNotMatch(JSON.stringify(first), /path|command|secret|host|credential/i);
});

test('gate, plan confirmation, sink, and dependency validation fail before mutations', async () => {
  for (const invalid of [
    { ...gate(), state: 'pending' },
    { ...gate(), extra: true },
    { ...gate(), pauseEvidence: { manifestId: 'bad', digest: digest('pause'), signature: 'bad=' } },
  ]) {
    await assert.rejects(() => planM4BackfillBatch({ gateVerifier: async () => invalid, maxEvents: 1 }), {
      code: 'm4_backfill_gate_invalid',
    });
  }
  const calls = [];
  const deps = dependencies([row(1)], { calls });
  await assert.rejects(() => runM4BackfillBatch({
    gateVerifier: async () => gate(), maxEvents: 1, confirmedPlanDigest: digest('wrong'), ...deps,
  }), { code: 'm4_backfill_plan_confirmation_invalid' });
  assert.deepEqual(calls, []);

  const plan = await planM4BackfillBatch({ gateVerifier: async () => gate(), maxEvents: 1 });
  await assert.rejects(() => runM4BackfillBatch({
    gateVerifier: async () => gate(), maxEvents: 1, confirmedPlanDigest: plan.planDigest,
    lease: {}, source: {}, outbox: {}, sink: {}, checkpointStore: {},
  }), { code: 'm4_backfill_dependency_invalid' });
});

test('successful batches heartbeat, enqueue, acknowledge, durable-commit, and release in order', async () => {
  const { result, deps, plan } = await confirmedRun([row(1), row(2)]);
  assert.equal(result.schema, 'amf.m4-backfill-result/v1');
  assert.equal(result.processed, 2);
  assert.equal(result.duplicates, 0);
  assert.equal(result.complete, true);
  assert.deepEqual(result.lastCheckpoint, { id: 'row-checkpoint-2', digest: digest('row-2') });
  assert.deepEqual(deps.calls.map(call => call[0]), [
    'acquire', 'load', 'open', 'heartbeat', 'enqueue', 'deliver', 'commit',
    'heartbeat', 'enqueue', 'deliver', 'commit', 'release',
  ]);
  assert.deepEqual(Object.keys(deps.calls.find(call => call[0] === 'open')[1]).sort(), [
    'after', 'maxEvents', 'phase', 'runId',
  ]);
  assert.equal(deps.committed.length, 2);
  assert.equal(deps.committed[0].planDigest, plan.planDigest);
});

test('checkpoint progress is plan-bound and checkpoints must advance', async () => {
  await assert.rejects(() => confirmedRun([row(2)], {
    loaded: plan => ({
      schema: 'amf.m4-backfill-progress/v1', runId: plan.runId, phase: plan.phase,
      planDigest: digest('stale-plan'), sequence: 1,
      checkpoint: { id: 'row-checkpoint-1', digest: digest('row-1') },
      eventId: event(1).eventId, payloadDigest: event(1).integrity.payloadDigest,
    }),
  }), { code: 'm4_backfill_progress_invalid' });
  await assert.rejects(() => confirmedRun([row(2, {
    checkpoint: { id: 'source-checkpoint-001', digest: digest('source') },
  })]), { code: 'm4_backfill_row_invalid' });
  await assert.rejects(() => planM4BackfillBatch({ gateVerifier: async () => gate(), maxEvents: 0 }), {
    code: 'm4_backfill_request_invalid',
  });
  await assert.rejects(() => planM4BackfillBatch({
    gateVerifier: async () => gate(), maxEvents: M4_BACKFILL_MAX_EVENTS + 1,
  }), { code: 'm4_backfill_request_invalid' });
});

test('durable acknowledgement and event-to-outbox identity mismatches stop before progress success', async () => {
  const plan = await planM4BackfillBatch({ gateVerifier: async () => gate(), maxEvents: 1 });
  const badAckDeps = dependencies([row(1)], {
    commitAcknowledgement: progress => ({ ...progressAcknowledgement(progress), committed: false }),
  });
  await assert.rejects(() => runM4BackfillBatch({
    gateVerifier: async () => gate(), maxEvents: 1, confirmedPlanDigest: plan.planDigest, ...badAckDeps,
  }), { code: 'm4_backfill_checkpoint_ack_invalid' });

  const wrongCheckpointDeps = dependencies([row(1)], {
    commitAcknowledgement: progress => ({
      ...progressAcknowledgement(progress),
      checkpoint: { id: 'row-checkpoint-wrong', digest: digest('wrong') },
    }),
  });
  await assert.rejects(() => runM4BackfillBatch({
    gateVerifier: async () => gate(), maxEvents: 1, confirmedPlanDigest: plan.planDigest, ...wrongCheckpointDeps,
  }), { code: 'm4_backfill_checkpoint_ack_invalid' });

  const receiptDeps = dependencies([row(1)]);
  receiptDeps.outbox.enqueue = async () => ({ ...acknowledgement(event(2)), state: 'pending' });
  await assert.rejects(() => runM4BackfillBatch({
    gateVerifier: async () => gate(), maxEvents: 1, confirmedPlanDigest: plan.planDigest, ...receiptDeps,
  }), { code: 'm4_backfill_enqueue_invalid' });
  assert.deepEqual(receiptDeps.committed, []);
});

test('checkpoint failure retries against the same durable outbox acknowledgement as a duplicate', async () => {
  const acknowledgements = new Map();
  const outbox = {
    async enqueue(value) {
      const prior = acknowledgements.get(value.eventId);
      return {
        eventId: value.eventId,
        payloadDigest: value.integrity.payloadDigest,
        state: prior ? 'acknowledged' : 'pending',
        duplicate: Boolean(prior),
      };
    },
    async deliver(eventId) {
      const prior = acknowledgements.get(eventId);
      if (prior) return { ...prior, duplicate: true };
      const created = acknowledgement(event(1), false);
      acknowledgements.set(eventId, created);
      return created;
    },
  };
  const gateVerifier = async () => gate();
  const plan = await planM4BackfillBatch({ gateVerifier, maxEvents: 1 });
  const first = dependencies([row(1)], { outbox, commitFailure: true });
  await assert.rejects(() => runM4BackfillBatch({
    gateVerifier, maxEvents: 1, confirmedPlanDigest: plan.planDigest, ...first,
  }), { code: 'm4_backfill_checkpoint_commit_failed' });
  const second = dependencies([row(1)], { outbox });
  const result = await runM4BackfillBatch({
    gateVerifier, maxEvents: 1, confirmedPlanDigest: plan.planDigest, ...second,
  });
  assert.equal(result.duplicates, 1);
  assert.equal(second.committed.length, 1);
});

test('mutation attempts cannot alter source binding, durable progress, or returned checkpoint', async () => {
  const { result, deps } = await confirmedRun([row(1)], {
    mutateOpen: input => { input.after.id = 'checkpoint-mutated'; },
    mutateCommit: progress => { progress.checkpoint.id = 'checkpoint-mutated'; },
  });
  assert.equal(deps.calls.find(call => call[0] === 'open')[1].after.id, 'checkpoint-mutated');
  assert.equal(deps.committed[0].checkpoint.id, 'row-checkpoint-1');
  assert.equal(result.lastCheckpoint.id, 'row-checkpoint-1');

  const noRows = await confirmedRun([], {
    mutateOpen: input => { input.after.id = 'checkpoint-mutated'; },
  });
  assert.equal(noRows.result.lastCheckpoint.id, 'source-checkpoint-001');
});

test('source bounds, iterator closure, and close/release precedence are fail-closed', async () => {
  const close = { count: 0 };
  const limited = await confirmedRun([row(1), row(2)], { maxEvents: 1, close });
  assert.equal(limited.result.complete, false);
  assert.equal(limited.result.processed, 1);
  assert.equal(close.count, 1);
  const exhausted = await confirmedRun([row(1)], { maxEvents: 1 });
  assert.equal(exhausted.result.complete, true);

  const closePlan = await planM4BackfillBatch({ gateVerifier: async () => gate(), maxEvents: 1 });
  const closeDeps = dependencies([row(1)], { close: { count: 0, fail: true }, releaseFailure: true });
  await assert.rejects(() => runM4BackfillBatch({
    gateVerifier: async () => gate(), maxEvents: 1, confirmedPlanDigest: closePlan.planDigest, ...closeDeps,
  }), { code: 'm4_backfill_source_close_failed' });
  assert.equal(closeDeps.calls.at(-1)[0], 'release');

  const releaseDeps = dependencies([row(1)], { releaseFailure: true });
  await assert.rejects(() => runM4BackfillBatch({
    gateVerifier: async () => gate(), maxEvents: 1, confirmedPlanDigest: closePlan.planDigest, ...releaseDeps,
  }), { code: 'm4_backfill_lease_release_failed' });
});

test('dependency exceptions cannot spoof coordinator errors or leak content', async () => {
  const plan = await planM4BackfillBatch({ gateVerifier: async () => gate(), maxEvents: 1 });
  const deps = dependencies([row(1)]);
  deps.outbox.enqueue = async () => {
    const error = new Error('SYNTHETIC_PRIVATE_EVENT');
    error.code = 'm4_backfill_plan_confirmation_invalid';
    throw error;
  };
  await assert.rejects(() => runM4BackfillBatch({
    gateVerifier: async () => gate(), maxEvents: 1, confirmedPlanDigest: plan.planDigest, ...deps,
  }), error => error.code === 'm4_backfill_enqueue_failed'
    && error.message === 'm4_backfill_enqueue_failed'
    && !Object.hasOwn(error, 'cause')
    && !error.message.includes('SYNTHETIC_PRIVATE_EVENT'));
});
