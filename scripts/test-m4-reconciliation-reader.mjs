import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

import {
  M4_DIMENSIONS,
  M4_MAX_MISMATCH_SAMPLES,
  M4_MAX_VISITED_EVENTS,
  reconcileM4,
} from '../src/migration/m4-reconciliation-reader.mjs';

const fixture = JSON.parse(fs.readFileSync(
  new URL('./fixtures/m4-reconciliation.synthetic.json', import.meta.url),
  'utf8',
));

const digest = marker => `sha256:${Buffer.from(String(marker), 'utf8').toString('hex').padEnd(64, '0').slice(0, 64)}`;
const eventId = number => `cevt_event${String(number).padStart(4, '0')}`;

function event(number, overrides = {}) {
  return {
    eventId: eventId(number),
    payloadDigest: digest(`payload-${number}`),
    logicalDigest: digest(`logical-${number}`),
    sourceOccurredAt: `2026-01-01T00:00:0${number}Z`,
    occurredAt: `2026-01-01T00:01:0${number}Z`,
    state: 'active',
    ...overrides,
  };
}

function checkpoint(name) {
  return { id: `checkpoint-${name}`, digest: digest(name) };
}

function staticEvidence(overrides = {}) {
  return {
    pausedInterval: { start: checkpoint('pause-start'), end: checkpoint('pause-end') },
    replayQueues: {
      pendingOutbox: checkpoint('pending'),
      acknowledgements: checkpoint('acknowledgements'),
      deadLetters: checkpoint('dead-letters'),
    },
    sourceCheckpoints: {
      collectorCursor: checkpoint('collector-cursor'),
      sourceCheckpoint: checkpoint('source-checkpoint'),
      nativeTranscriptAuthority: checkpoint('native-authority'),
    },
    ...overrides,
  };
}

function iterable(rows) {
  return (async function* rowsIterable() { yield* rows; }());
}

function dimension(report, name) {
  return report.dimensionEvidence.find(entry => entry.name === name);
}

async function reconciliation(sourceRows, targetRows, options = {}) {
  return reconcileM4({
    source: iterable(sourceRows),
    target: iterable(targetRows),
    sourceEvidence: staticEvidence(),
    targetEvidence: staticEvidence(),
    ...options,
  });
}

test('exact match is deterministic, compact, and complete', async () => {
  const rows = [
    event(1),
    event(2, { state: 'edited', replacesEventId: eventId(1) }),
    event(3, { state: 'replacement', replacesEventId: eventId(2) }),
    event(4, { state: 'tombstone', tombstonesEventId: eventId(3) }),
    event(5, { state: 'conflict', conflictsWithEventIds: [eventId(1), eventId(4)] }),
  ];
  const first = await reconciliation(rows, rows);
  const second = await reconciliation(rows, rows);

  assert.equal(first.state, 'complete');
  assert.equal(first.unresolvedMismatchCount, 0);
  assert.equal(first.completeness, 1);
  assert.equal(first.tolerance, 0);
  assert.deepEqual(first.dimensions, M4_DIMENSIONS);
  assert.deepEqual(first.dimensionsBinding, second.dimensionsBinding);
  for (const entry of first.dimensionEvidence) {
    assert.equal(entry.match, true);
    assert.equal(entry.mismatchCount, 0);
    assert.ok(!Array.isArray(entry.source));
  }
  assert.deepEqual(dimension(first, 'time-ranges').source.sourceOccurredAt, {
    min: '2026-01-01T00:00:01Z', max: '2026-01-01T00:00:05Z',
  });
  assert.deepEqual(dimension(first, 'time-ranges').source.occurredAt, {
    min: '2026-01-01T00:01:01Z', max: '2026-01-01T00:01:05Z',
  });
});

test('the synthetic fixture remains valid and exercises an exact reconciliation', async () => {
  assert.equal(fixture.schema, 'amf.m4-reconciliation-fixture/v1');
  assert.match(fixture.description, /^Synthetic, content-free /);
  assert.equal(fixture.events.length, 3);
  const report = await reconcileM4({
    source: iterable(fixture.events),
    target: iterable(fixture.events),
    sourceEvidence: fixture.staticEvidence,
    targetEvidence: fixture.staticEvidence,
  });
  assert.equal(report.state, 'complete');
  assert.equal(report.unresolvedMismatchCount, 0);
});

test('missing and extra IDs count each affected dimension without false count mismatch', async () => {
  const report = await reconciliation([event(1)], [event(2)]);
  assert.equal(dimension(report, 'counts').mismatchCount, 0);
  for (const name of ['stable-ids', 'payload-digests', 'logical-digests', 'time-ranges']) {
    assert.equal(dimension(report, name).mismatchCount, 2);
  }
  assert.equal(report.unresolvedMismatchCount, 8);
  assert.equal(report.state, 'pending');
});

test('same ID comparisons isolate payload, logical, and time differences', async () => {
  const source = event(1);
  const target = {
    ...source,
    payloadDigest: digest('changed-payload'),
    logicalDigest: digest('changed-logical'),
    occurredAt: '2026-01-01T00:01:09Z',
  };
  const report = await reconciliation([source], [target]);
  assert.equal(dimension(report, 'payload-digests').mismatchCount, 1);
  assert.equal(dimension(report, 'logical-digests').mismatchCount, 1);
  assert.equal(dimension(report, 'time-ranges').mismatchCount, 1);
  for (const name of ['stable-ids', 'edits', 'replacements', 'tombstones', 'conflicts']) {
    assert.equal(dimension(report, name).mismatchCount, 0);
  }
});

test('relationship dimensions compare only their own content-free projections', async () => {
  const source = [
    event(1, { state: 'edited', replacesEventId: eventId(9) }),
    event(2, { state: 'replacement', replacesEventId: eventId(8) }),
    event(3, { state: 'tombstone', tombstonesEventId: eventId(7) }),
    event(4, { state: 'conflict', conflictsWithEventIds: [eventId(5)] }),
  ];
  const target = [
    event(1, { state: 'edited', replacesEventId: eventId(8) }),
    event(2, { state: 'replacement', replacesEventId: eventId(7) }),
    event(3, { state: 'tombstone', tombstonesEventId: eventId(6) }),
    event(4, { state: 'conflict', conflictsWithEventIds: [eventId(6)] }),
  ];
  const report = await reconciliation(source, target);
  for (const name of ['edits', 'replacements', 'tombstones', 'conflicts']) {
    assert.equal(dimension(report, name).mismatchCount, 1);
  }
  assert.equal(dimension(report, 'payload-digests').mismatchCount, 0);
  assert.equal(dimension(report, 'logical-digests').mismatchCount, 0);
});

test('static evidence counts every differing leaf and is copied before streams run', async () => {
  const sourceEvidence = staticEvidence();
  const targetEvidence = staticEvidence({
    pausedInterval: { start: checkpoint('other-start'), end: checkpoint('pause-end') },
    replayQueues: {
      pendingOutbox: checkpoint('other-pending'),
      acknowledgements: checkpoint('acknowledgements'),
      deadLetters: checkpoint('other-dead'),
    },
    sourceCheckpoints: {
      collectorCursor: checkpoint('collector-cursor'),
      sourceCheckpoint: checkpoint('other-source'),
      nativeTranscriptAuthority: checkpoint('other-native'),
    },
  });
  const delayedSource = {
    async *[Symbol.asyncIterator]() {
      sourceEvidence.pausedInterval.start.id = 'checkpoint-mutated';
      yield event(1);
    },
  };
  const report = await reconcileM4({
    source: delayedSource,
    target: iterable([event(1)]),
    sourceEvidence,
    targetEvidence,
  });
  assert.equal(dimension(report, 'paused-interval').mismatchCount, 1);
  assert.equal(dimension(report, 'replay-queues').mismatchCount, 2);
  assert.equal(dimension(report, 'source-checkpoints').mismatchCount, 2);
  assert.equal(dimension(report, 'paused-interval').source.start.id, 'checkpoint-pause-start');
});

test('bounds, ordering failures, and invalid initial reads close both iterators', async () => {
  const sourceClose = { count: 0 };
  const targetClose = { count: 0 };
  function tracked(rows, close, rejectFirst = false) {
    return {
      [Symbol.asyncIterator]() {
        let index = 0;
        return {
          async next() {
            if (rejectFirst && index++ === 0) throw Object.assign(new Error('input'), { code: 'input' });
            return index < rows.length ? { value: rows[index++], done: false } : { done: true };
          },
          async return() { close.count += 1; return { done: true }; },
        };
      },
    };
  }

  await assert.rejects(() => reconcileM4({
    source: tracked([event(1), event(2)], sourceClose),
    target: tracked([event(1), event(2)], targetClose),
    sourceEvidence: staticEvidence(), targetEvidence: staticEvidence(), maxVisitedEvents: 3,
  }), { code: 'm4_reconciliation_event_limit_exceeded' });
  assert.equal(sourceClose.count, 1);
  assert.equal(targetClose.count, 1);

  const firstClose = { count: 0 };
  const otherClose = { count: 0 };
  await assert.rejects(() => reconcileM4({
    source: tracked([], firstClose, true), target: tracked([], otherClose),
    sourceEvidence: staticEvidence(), targetEvidence: staticEvidence(),
  }), { code: 'input' });
  assert.equal(firstClose.count, 1);
  assert.equal(otherClose.count, 1);

  const noSamples = await reconciliation([event(1)], [event(2)], { maxMismatchSamples: 0 });
  assert.deepEqual(noSamples.mismatchSamples, []);
  const bounded = await reconciliation([event(1), event(3)], [event(2), event(4)], { maxMismatchSamples: 2 });
  assert.equal(bounded.mismatchSamples.length, 2);
  assert.deepEqual(Object.keys(bounded.mismatchSamples[0]).sort(), ['dimension', 'eventId', 'kind']);
  await assert.rejects(() => reconciliation([event(2), event(1)], [event(1), event(2)]), {
    code: 'm4_reconciliation_order_invalid',
  });
  await assert.rejects(() => reconciliation([event(1), event(1)], [event(1), event(2)]), {
    code: 'm4_reconciliation_order_invalid',
  });
  await assert.rejects(() => reconciliation([], [], {
    maxVisitedEvents: M4_MAX_VISITED_EVENTS + 1,
  }), { code: 'm4_reconciliation_request_invalid' });
  await assert.rejects(() => reconciliation([], [], {
    maxMismatchSamples: M4_MAX_MISMATCH_SAMPLES + 1,
  }), { code: 'm4_reconciliation_request_invalid' });
});

test('visited event budget counts each yielded source and target row exactly once', async () => {
  const asymmetricSource = [event(1), event(2), event(3)];
  const asymmetricTarget = [event(3)];
  const exact = await reconciliation(asymmetricSource, asymmetricTarget, { maxVisitedEvents: 4 });
  assert.equal(exact.state, 'pending');
  await assert.rejects(() => reconciliation(asymmetricSource, asymmetricTarget, {
    maxVisitedEvents: 3,
  }), { code: 'm4_reconciliation_event_limit_exceeded' });

  const matching = await reconciliation([event(1)], [event(1)], { maxVisitedEvents: 2 });
  assert.equal(matching.state, 'complete');
  await assert.rejects(() => reconciliation([event(1)], [event(1)], {
    maxVisitedEvents: 1,
  }), { code: 'm4_reconciliation_event_limit_exceeded' });

  const doneDoesNotConsumeBudget = await reconciliation([event(1)], [], { maxVisitedEvents: 1 });
  assert.equal(doneDoesNotConsumeBudget.state, 'pending');
});

test('iterator construction failures and invalid iterator shapes close a created source iterator', async () => {
  const closed = { count: 0 };
  const source = {
    [Symbol.asyncIterator]() {
      return {
        async next() { return { done: true }; },
        async return() { closed.count += 1; return { done: true }; },
      };
    },
  };
  const throwingTarget = {
    [Symbol.asyncIterator]() {
      throw Object.assign(new Error('target construction failed'), { code: 'target_iterator_failed' });
    },
  };
  await assert.rejects(() => reconcileM4({
    source,
    target: throwingTarget,
    sourceEvidence: staticEvidence(),
    targetEvidence: staticEvidence(),
  }), { code: 'target_iterator_failed' });
  assert.equal(closed.count, 1);

  const invalidClosed = { count: 0 };
  const invalidSource = {
    [Symbol.asyncIterator]() {
      return {
        async next() { return { done: true }; },
        async return() { invalidClosed.count += 1; return { done: true }; },
      };
    },
  };
  await assert.rejects(() => reconcileM4({
    source: invalidSource,
    target: { [Symbol.asyncIterator]: () => ({}) },
    sourceEvidence: staticEvidence(),
    targetEvidence: staticEvidence(),
  }), { code: 'm4_reconciliation_request_invalid' });
  assert.equal(invalidClosed.count, 1);
});

test('mismatch sample options are bounded, deterministic, and binding-relevant', async () => {
  const source = [event(1), event(3)];
  const target = [event(2), event(4)];
  const oneSample = await reconciliation(source, target, { maxMismatchSamples: 1 });
  const sameOneSample = await reconciliation(source, target, { maxMismatchSamples: 1 });
  const twoSamples = await reconciliation(source, target, { maxMismatchSamples: 2 });

  assert.equal(oneSample.mismatchSamples.length, 1);
  assert.deepEqual(oneSample.dimensionsBinding, sameOneSample.dimensionsBinding);
  assert.equal(twoSamples.mismatchSamples.length, 2);
  assert.notDeepEqual(oneSample.dimensionsBinding, twoSamples.dimensionsBinding);
});

test('event and static validation reject forbidden, malformed, and ambiguous projections', async () => {
  const invalidEvents = [
    { ...event(1), visibleText: 'forbidden' },
    { ...event(1), sourceOccurredAt: '2026-02-30T00:00:00Z' },
    { ...event(1), sourceOccurredAt: '2026-01-01T00:00:01+00:00' },
    { ...event(1), state: 'active', replacesEventId: eventId(2) },
    { ...event(1), state: 'conflict' },
    { ...event(1), state: 'conflict', conflictsWithEventIds: [eventId(3), eventId(2)] },
    { ...event(1), state: 'edited' },
    { ...event(1), replacesEventId: undefined },
  ];
  for (const invalid of invalidEvents) {
    await assert.rejects(() => reconciliation([invalid], [event(1)]), {
      code: 'm4_reconciliation_event_invalid',
    });
  }
  const invalidEvidence = staticEvidence({
    replayQueues: {
      pendingOutbox: checkpoint('pending'),
      acknowledgements: checkpoint('acknowledgements'),
      deadLetters: { ...checkpoint('dead'), command: 'forbidden' },
    },
  });
  await assert.rejects(() => reconcileM4({
    source: iterable([]), target: iterable([]),
    sourceEvidence: invalidEvidence, targetEvidence: staticEvidence(),
  }), { code: 'm4_reconciliation_static_evidence_invalid' });
});
