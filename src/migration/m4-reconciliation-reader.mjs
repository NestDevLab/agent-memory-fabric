import crypto from 'node:crypto';

import { canonicalJson, strictIsoTimestamp } from '../ingest/transcripts/canonical.mjs';

export const M4_DIMENSIONS = Object.freeze([
  'counts', 'stable-ids', 'payload-digests', 'logical-digests', 'time-ranges',
  'edits', 'replacements', 'tombstones', 'conflicts', 'paused-interval',
  'replay-queues', 'source-checkpoints',
]);
export const M4_MAX_VISITED_EVENTS = 5_000_000;
export const M4_MAX_MISMATCH_SAMPLES = 1_000;

const EVENT_DIMENSIONS = M4_DIMENSIONS.slice(0, 9);
const RELATIONSHIP_DIMENSIONS = [
  ['edits', 'edited'],
  ['replacements', 'replacement'],
  ['tombstones', 'tombstone'],
  ['conflicts', 'conflict'],
];
const EVENT_ID_PATTERN = /^cevt_[a-z0-9][a-z0-9_-]{7,127}$/;
const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/;
const CHECKPOINT_ID_PATTERN = /^[a-z][a-z0-9-]{2,79}$/;
const STATES = new Set(['active', 'edited', 'replacement', 'tombstone', 'conflict']);
const CORE_EVENT_KEYS = [
  'eventId', 'payloadDigest', 'logicalDigest', 'sourceOccurredAt', 'occurredAt', 'state',
];
const OPTIONAL_EVENT_KEYS = ['replacesEventId', 'tombstonesEventId', 'conflictsWithEventIds'];
const ALLOWED_EVENT_KEYS = new Set([...CORE_EVENT_KEYS, ...OPTIONAL_EVENT_KEYS]);

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype;
}

function isStrictUtcTimestamp(value) {
  if (strictIsoTimestamp(value) !== value || !value.endsWith('Z')) return false;
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?Z$/.exec(value);
  if (!match) return false;
  const [, yearText, monthText, dayText, hourText, minuteText, secondText] = match;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);
  if (month < 1 || month > 12 || hour > 23 || minute > 59 || second > 59) return false;
  const probe = new Date(Date.UTC(year, month - 1, day));
  return probe.getUTCFullYear() === year
    && probe.getUTCMonth() === month - 1
    && probe.getUTCDate() === day;
}

function validateEvent(value) {
  if (!isPlainObject(value)) fail('m4_reconciliation_event_invalid');
  const keys = Object.keys(value);
  if (keys.some(key => !ALLOWED_EVENT_KEYS.has(key))
    || CORE_EVENT_KEYS.some(key => !Object.hasOwn(value, key))) {
    fail('m4_reconciliation_event_invalid');
  }
  if (typeof value.eventId !== 'string' || !EVENT_ID_PATTERN.test(value.eventId)
    || typeof value.payloadDigest !== 'string' || !DIGEST_PATTERN.test(value.payloadDigest)
    || typeof value.logicalDigest !== 'string' || !DIGEST_PATTERN.test(value.logicalDigest)
    || !isStrictUtcTimestamp(value.sourceOccurredAt)
    || !isStrictUtcTimestamp(value.occurredAt)
    || typeof value.state !== 'string' || !STATES.has(value.state)) {
    fail('m4_reconciliation_event_invalid');
  }

  const hasReplacement = Object.hasOwn(value, 'replacesEventId');
  const hasTombstone = Object.hasOwn(value, 'tombstonesEventId');
  const hasConflicts = Object.hasOwn(value, 'conflictsWithEventIds');
  if (hasReplacement && (typeof value.replacesEventId !== 'string' || !EVENT_ID_PATTERN.test(value.replacesEventId))) {
    fail('m4_reconciliation_event_invalid');
  }
  if (hasTombstone && (typeof value.tombstonesEventId !== 'string' || !EVENT_ID_PATTERN.test(value.tombstonesEventId))) {
    fail('m4_reconciliation_event_invalid');
  }
  if (hasConflicts) {
    const ids = value.conflictsWithEventIds;
    if (!Array.isArray(ids) || ids.length < 1 || ids.length > 32
      || ids.some(id => typeof id !== 'string' || !EVENT_ID_PATTERN.test(id))
      || ids.some((id, index) => index > 0 && ids[index - 1] >= id)) {
      fail('m4_reconciliation_event_invalid');
    }
  }

  const requiresReplacement = value.state === 'edited' || value.state === 'replacement';
  if ((requiresReplacement !== hasReplacement)
    || ((value.state === 'tombstone') !== hasTombstone)
    || ((value.state === 'conflict') !== hasConflicts)
    || (value.state === 'active' && (hasReplacement || hasTombstone || hasConflicts))
    || (value.state !== 'conflict' && hasConflicts)
    || (value.state !== 'tombstone' && hasTombstone)
    || (!requiresReplacement && hasReplacement)) {
    fail('m4_reconciliation_event_invalid');
  }

  const normalized = {
    eventId: value.eventId,
    payloadDigest: value.payloadDigest,
    logicalDigest: value.logicalDigest,
    sourceOccurredAt: value.sourceOccurredAt,
    occurredAt: value.occurredAt,
    state: value.state,
  };
  if (hasReplacement) normalized.replacesEventId = value.replacesEventId;
  if (hasTombstone) normalized.tombstonesEventId = value.tombstonesEventId;
  if (hasConflicts) normalized.conflictsWithEventIds = [...value.conflictsWithEventIds];
  return normalized;
}

function validateCheckpoint(value) {
  if (!isPlainObject(value)
    || Object.keys(value).length !== 2
    || !Object.hasOwn(value, 'id')
    || !Object.hasOwn(value, 'digest')
    || typeof value.id !== 'string'
    || !CHECKPOINT_ID_PATTERN.test(value.id)
    || typeof value.digest !== 'string'
    || !DIGEST_PATTERN.test(value.digest)) {
    fail('m4_reconciliation_static_evidence_invalid');
  }
  return { id: value.id, digest: value.digest };
}

function validateEvidenceMap(value, keys) {
  if (!isPlainObject(value)
    || Object.keys(value).length !== keys.length
    || keys.some(key => !Object.hasOwn(value, key))) {
    fail('m4_reconciliation_static_evidence_invalid');
  }
  return Object.fromEntries(keys.map(key => [key, validateCheckpoint(value[key])]));
}

function validateStaticEvidence(value) {
  const keys = ['pausedInterval', 'replayQueues', 'sourceCheckpoints'];
  if (!isPlainObject(value)
    || Object.keys(value).length !== keys.length
    || keys.some(key => !Object.hasOwn(value, key))) {
    fail('m4_reconciliation_static_evidence_invalid');
  }
  return {
    pausedInterval: validateEvidenceMap(value.pausedInterval, ['start', 'end']),
    replayQueues: validateEvidenceMap(value.replayQueues, [
      'pendingOutbox', 'acknowledgements', 'deadLetters',
    ]),
    sourceCheckpoints: validateEvidenceMap(value.sourceCheckpoints, [
      'collectorCursor', 'sourceCheckpoint', 'nativeTranscriptAuthority',
    ]),
  };
}

function evidenceDomain(dimension) {
  return `amf.m4.${dimension}.v1`;
}

function newAccumulator(dimension) {
  const hash = crypto.createHash('sha256');
  hash.update(Buffer.from(`${evidenceDomain(dimension)}\u0000`, 'utf8'));
  return {
    count: 0,
    hash,
    sourceOccurredAt: { min: null, max: null },
    occurredAt: { min: null, max: null },
  };
}

function updateHash(accumulator, domain, value) {
  const encoded = Buffer.from(canonicalJson(value), 'utf8');
  accumulator.hash.update(Buffer.from(`${domain}\u0000${encoded.length}\u0000`, 'utf8'));
  accumulator.hash.update(encoded);
}

function updateRange(range, value) {
  range.min = range.min === null || value < range.min ? value : range.min;
  range.max = range.max === null || value > range.max ? value : range.max;
}

function addEvidence(accumulator, dimension, value, event = null) {
  accumulator.count += 1;
  updateHash(accumulator, evidenceDomain(dimension), value);
  if (event !== null) {
    updateRange(accumulator.sourceOccurredAt, event.sourceOccurredAt);
    updateRange(accumulator.occurredAt, event.occurredAt);
  }
}

function compactEvidence(accumulator, includeTimeRanges = false) {
  const evidence = {
    count: accumulator.count,
    digest: `sha256:${accumulator.hash.digest('hex')}`,
  };
  if (includeTimeRanges) {
    evidence.sourceOccurredAt = { ...accumulator.sourceOccurredAt };
    evidence.occurredAt = { ...accumulator.occurredAt };
  }
  return evidence;
}

function newEventAccumulators() {
  return Object.fromEntries(EVENT_DIMENSIONS.map(dimension => [
    dimension,
    [newAccumulator(dimension), newAccumulator(dimension)],
  ]));
}

function relationshipProjection(dimension, event) {
  if (dimension === 'edits' && event.state === 'edited') return [event.eventId, event.replacesEventId];
  if (dimension === 'replacements' && event.state === 'replacement') return [event.eventId, event.replacesEventId];
  if (dimension === 'tombstones' && event.state === 'tombstone') return [event.eventId, event.tombstonesEventId];
  if (dimension === 'conflicts' && event.state === 'conflict') return [event.eventId, event.conflictsWithEventIds];
  return null;
}

function addEvent(accumulators, side, event) {
  addEvidence(accumulators.counts[side], 'counts', null);
  addEvidence(accumulators['stable-ids'][side], 'stable-ids', event.eventId);
  addEvidence(accumulators['payload-digests'][side], 'payload-digests', [event.eventId, event.payloadDigest]);
  addEvidence(accumulators['logical-digests'][side], 'logical-digests', [event.eventId, event.logicalDigest]);
  addEvidence(accumulators['time-ranges'][side], 'time-ranges', [
    event.eventId, event.sourceOccurredAt, event.occurredAt,
  ], event);
  for (const [dimension] of RELATIONSHIP_DIMENSIONS) {
    const projection = relationshipProjection(dimension, event);
    if (projection !== null) addEvidence(accumulators[dimension][side], dimension, projection);
  }
}

function eventDimensionsForRow(event) {
  const dimensions = ['stable-ids', 'payload-digests', 'logical-digests', 'time-ranges'];
  for (const [dimension] of RELATIONSHIP_DIMENSIONS) {
    if (relationshipProjection(dimension, event) !== null) dimensions.push(dimension);
  }
  return dimensions;
}

function recordMismatch(mismatches, samples, maxMismatchSamples, eventId, dimension, kind) {
  mismatches[dimension] += 1;
  if (samples.length < maxMismatchSamples) samples.push({ eventId, dimension, kind });
}

function staticDimensionKey(dimension) {
  if (dimension === 'paused-interval') return 'pausedInterval';
  if (dimension === 'replay-queues') return 'replayQueues';
  return 'sourceCheckpoints';
}

function countStaticMismatches(source, target) {
  return Object.keys(source).filter(key => canonicalJson(source[key]) !== canonicalJson(target[key])).length;
}

function equalJson(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function assertReportInvariant(dimensionEvidence) {
  for (const dimension of dimensionEvidence) {
    const evidenceMatches = equalJson(dimension.source, dimension.target);
    if ((dimension.mismatchCount === 0) !== evidenceMatches || dimension.match !== evidenceMatches) {
      fail('m4_reconciliation_invariant_failed');
    }
  }
}

function digest(value) {
  return `sha256:${crypto.createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`;
}

async function closeIterator(iterator) {
  if (iterator === null) return;
  try {
    await iterator.return?.();
  } catch {
    // Closing is best effort; the typed comparison failure remains authoritative.
  }
}

async function readNext(iterator, visitBudget) {
  const next = await iterator.next();
  if (!next.done) {
    if (visitBudget.visitedEvents >= visitBudget.maxVisitedEvents) {
      fail('m4_reconciliation_event_limit_exceeded');
    }
    visitBudget.visitedEvents += 1;
  }
  return next;
}

function validateAsyncIterator(iterator) {
  if (iterator === null || typeof iterator !== 'object' || typeof iterator.next !== 'function') {
    fail('m4_reconciliation_request_invalid');
  }
  return iterator;
}

export async function reconcileM4({
  source,
  target,
  sourceEvidence,
  targetEvidence,
  maxVisitedEvents = 10_000,
  maxMismatchSamples = 100,
} = {}) {
  if (typeof source?.[Symbol.asyncIterator] !== 'function'
    || typeof target?.[Symbol.asyncIterator] !== 'function'
    || !Number.isSafeInteger(maxVisitedEvents)
    || maxVisitedEvents < 1
    || maxVisitedEvents > M4_MAX_VISITED_EVENTS
    || !Number.isSafeInteger(maxMismatchSamples)
    || maxMismatchSamples < 0
    || maxMismatchSamples > M4_MAX_MISMATCH_SAMPLES) {
    fail('m4_reconciliation_request_invalid');
  }

  const safeSourceEvidence = validateStaticEvidence(sourceEvidence);
  const safeTargetEvidence = validateStaticEvidence(targetEvidence);
  const accumulators = newEventAccumulators();
  const mismatches = Object.fromEntries(M4_DIMENSIONS.map(dimension => [dimension, 0]));
  const mismatchSamples = [];
  const priorIds = [null, null];
  const visitBudget = { visitedEvents: 0, maxVisitedEvents };
  let sourceIterator = null;
  let targetIterator = null;

  try {
    sourceIterator = validateAsyncIterator(source[Symbol.asyncIterator]());
    targetIterator = validateAsyncIterator(target[Symbol.asyncIterator]());
    let sourceNext = await readNext(sourceIterator, visitBudget);
    let targetNext = await readNext(targetIterator, visitBudget);
    while (!sourceNext.done || !targetNext.done) {
      const sourceEvent = sourceNext.done ? null : validateEvent(sourceNext.value);
      const targetEvent = targetNext.done ? null : validateEvent(targetNext.value);
      if (sourceEvent !== null && priorIds[0] !== null && priorIds[0] >= sourceEvent.eventId) {
        fail('m4_reconciliation_order_invalid');
      }
      if (targetEvent !== null && priorIds[1] !== null && priorIds[1] >= targetEvent.eventId) {
        fail('m4_reconciliation_order_invalid');
      }

      if (targetEvent === null || (sourceEvent !== null && sourceEvent.eventId < targetEvent.eventId)) {
        addEvent(accumulators, 0, sourceEvent);
        for (const dimension of eventDimensionsForRow(sourceEvent)) {
          recordMismatch(mismatches, mismatchSamples, maxMismatchSamples,
            sourceEvent.eventId, dimension, 'missing-target');
        }
        priorIds[0] = sourceEvent.eventId;
        sourceNext = await readNext(sourceIterator, visitBudget);
        continue;
      }
      if (sourceEvent === null || targetEvent.eventId < sourceEvent.eventId) {
        addEvent(accumulators, 1, targetEvent);
        for (const dimension of eventDimensionsForRow(targetEvent)) {
          recordMismatch(mismatches, mismatchSamples, maxMismatchSamples,
            targetEvent.eventId, dimension, 'extra-target');
        }
        priorIds[1] = targetEvent.eventId;
        targetNext = await readNext(targetIterator, visitBudget);
        continue;
      }

      addEvent(accumulators, 0, sourceEvent);
      addEvent(accumulators, 1, targetEvent);
      if (sourceEvent.payloadDigest !== targetEvent.payloadDigest) {
        recordMismatch(mismatches, mismatchSamples, maxMismatchSamples,
          sourceEvent.eventId, 'payload-digests', 'different');
      }
      if (sourceEvent.logicalDigest !== targetEvent.logicalDigest) {
        recordMismatch(mismatches, mismatchSamples, maxMismatchSamples,
          sourceEvent.eventId, 'logical-digests', 'different');
      }
      if (sourceEvent.sourceOccurredAt !== targetEvent.sourceOccurredAt
        || sourceEvent.occurredAt !== targetEvent.occurredAt) {
        recordMismatch(mismatches, mismatchSamples, maxMismatchSamples,
          sourceEvent.eventId, 'time-ranges', 'different');
      }
      for (const [dimension] of RELATIONSHIP_DIMENSIONS) {
        if (!equalJson(relationshipProjection(dimension, sourceEvent), relationshipProjection(dimension, targetEvent))) {
          recordMismatch(mismatches, mismatchSamples, maxMismatchSamples,
            sourceEvent.eventId, dimension, 'different');
        }
      }
      priorIds[0] = sourceEvent.eventId;
      priorIds[1] = targetEvent.eventId;
      sourceNext = await readNext(sourceIterator, visitBudget);
      targetNext = await readNext(targetIterator, visitBudget);
    }
  } finally {
    await Promise.all([closeIterator(sourceIterator), closeIterator(targetIterator)]);
  }

  mismatches.counts = Math.abs(accumulators.counts[0].count - accumulators.counts[1].count);
  for (const dimension of ['paused-interval', 'replay-queues', 'source-checkpoints']) {
    const key = staticDimensionKey(dimension);
    mismatches[dimension] = countStaticMismatches(safeSourceEvidence[key], safeTargetEvidence[key]);
  }

  const dimensionEvidence = M4_DIMENSIONS.map(dimension => {
    const isEventDimension = EVENT_DIMENSIONS.includes(dimension);
    const sourceEvidenceForDimension = isEventDimension
      ? compactEvidence(accumulators[dimension][0], dimension === 'time-ranges')
      : safeSourceEvidence[staticDimensionKey(dimension)];
    const targetEvidenceForDimension = isEventDimension
      ? compactEvidence(accumulators[dimension][1], dimension === 'time-ranges')
      : safeTargetEvidence[staticDimensionKey(dimension)];
    return {
      name: dimension,
      source: sourceEvidenceForDimension,
      target: targetEvidenceForDimension,
      mismatchCount: mismatches[dimension],
      match: mismatches[dimension] === 0,
    };
  });
  assertReportInvariant(dimensionEvidence);

  const unresolvedMismatchCount = Object.values(mismatches)
    .reduce((sum, mismatchCount) => sum + mismatchCount, 0);
  const state = unresolvedMismatchCount === 0 ? 'complete' : 'pending';
  const bindingPayload = {
    schema: 'amf.m4-reconciliation-report/v1',
    dimensions: M4_DIMENSIONS,
    dimensionEvidence,
    unresolvedMismatchCount,
    completeness: 1,
    tolerance: 0,
    state,
    mismatchSamples,
  };
  const bindingDigest = digest(bindingPayload);
  return {
    ...bindingPayload,
    dimensionsBinding: {
      id: `m4-binding-${bindingDigest.slice('sha256:'.length)}`,
      digest: bindingDigest,
    },
  };
}

function validateReportRange(value, count) {
  if (!isPlainObject(value) || Object.keys(value).length !== 2
    || !Object.hasOwn(value, 'min') || !Object.hasOwn(value, 'max')) {
    fail('m4_reconciliation_report_invalid');
  }
  const valid = item => item === null || (typeof item === 'string' && isStrictUtcTimestamp(item));
  if (!valid(value.min) || !valid(value.max)
    || (count === 0) !== (value.min === null && value.max === null)
    || (count > 0 && (value.min === null || value.max === null || value.min > value.max))) {
    fail('m4_reconciliation_report_invalid');
  }
  return { min: value.min, max: value.max };
}

function validateReportCompactEvidence(value, includeRanges) {
  const keys = includeRanges
    ? ['count', 'digest', 'sourceOccurredAt', 'occurredAt']
    : ['count', 'digest'];
  if (!isPlainObject(value) || Object.keys(value).length !== keys.length
    || keys.some(key => !Object.hasOwn(value, key))
    || !Number.isSafeInteger(value.count) || value.count < 0
    || typeof value.digest !== 'string' || !DIGEST_PATTERN.test(value.digest)) {
    fail('m4_reconciliation_report_invalid');
  }
  return {
    count: value.count,
    digest: value.digest,
    ...(includeRanges ? {
      sourceOccurredAt: validateReportRange(value.sourceOccurredAt, value.count),
      occurredAt: validateReportRange(value.occurredAt, value.count),
    } : {}),
  };
}

function validateReportDimensionEvidence(value, index) {
  const keys = ['name', 'source', 'target', 'mismatchCount', 'match'];
  if (!isPlainObject(value) || Object.keys(value).length !== keys.length
    || keys.some(key => !Object.hasOwn(value, key))
    || value.name !== M4_DIMENSIONS[index]
    || !Number.isSafeInteger(value.mismatchCount) || value.mismatchCount < 0
    || typeof value.match !== 'boolean' || value.match !== (value.mismatchCount === 0)) {
    fail('m4_reconciliation_report_invalid');
  }
  let source;
  let target;
  if (EVENT_DIMENSIONS.includes(value.name)) {
    const includeRanges = value.name === 'time-ranges';
    source = validateReportCompactEvidence(value.source, includeRanges);
    target = validateReportCompactEvidence(value.target, includeRanges);
  } else {
    const keysByDimension = {
      'paused-interval': ['start', 'end'],
      'replay-queues': ['pendingOutbox', 'acknowledgements', 'deadLetters'],
      'source-checkpoints': ['collectorCursor', 'sourceCheckpoint', 'nativeTranscriptAuthority'],
    };
    source = validateEvidenceMap(value.source, keysByDimension[value.name]);
    target = validateEvidenceMap(value.target, keysByDimension[value.name]);
  }
  return {
    name: value.name,
    source,
    target,
    mismatchCount: value.mismatchCount,
    match: value.match,
  };
}

function validateReportSamples(value, dimensionEvidence) {
  if (!Array.isArray(value) || value.length > M4_MAX_MISMATCH_SAMPLES) {
    fail('m4_reconciliation_report_invalid');
  }
  const mismatchByDimension = new Map(dimensionEvidence.map(item => [item.name, item.mismatchCount]));
  const sampledDimensions = new Set(EVENT_DIMENSIONS.filter(name => name !== 'counts'));
  return value.map(sample => {
    const keys = ['eventId', 'dimension', 'kind'];
    if (!isPlainObject(sample) || Object.keys(sample).length !== keys.length
      || keys.some(key => !Object.hasOwn(sample, key))
      || typeof sample.eventId !== 'string' || !EVENT_ID_PATTERN.test(sample.eventId)
      || typeof sample.dimension !== 'string' || !sampledDimensions.has(sample.dimension)
      || !['missing-target', 'extra-target', 'different'].includes(sample.kind)
      || mismatchByDimension.get(sample.dimension) < 1) {
      fail('m4_reconciliation_report_invalid');
    }
    return { eventId: sample.eventId, dimension: sample.dimension, kind: sample.kind };
  });
}

export function validateM4ReconciliationReport(value) {
  try {
    const report = structuredClone(value);
    const keys = [
      'schema', 'dimensions', 'dimensionEvidence', 'unresolvedMismatchCount',
      'completeness', 'tolerance', 'state', 'mismatchSamples', 'dimensionsBinding',
    ];
    if (!isPlainObject(report) || Object.keys(report).length !== keys.length
      || keys.some(key => !Object.hasOwn(report, key))
      || report.schema !== 'amf.m4-reconciliation-report/v1'
      || canonicalJson(report.dimensions) !== canonicalJson(M4_DIMENSIONS)
      || !Array.isArray(report.dimensionEvidence)
      || report.dimensionEvidence.length !== M4_DIMENSIONS.length
      || !Number.isSafeInteger(report.unresolvedMismatchCount) || report.unresolvedMismatchCount < 0
      || report.completeness !== 1 || report.tolerance !== 0
      || !['pending', 'complete'].includes(report.state)) {
      fail('m4_reconciliation_report_invalid');
    }
    const dimensionEvidence = report.dimensionEvidence
      .map((item, index) => validateReportDimensionEvidence(item, index));
    assertReportInvariant(dimensionEvidence);
    const mismatchSamples = validateReportSamples(report.mismatchSamples, dimensionEvidence);
    const unresolvedMismatchCount = dimensionEvidence
      .reduce((sum, item) => sum + item.mismatchCount, 0);
    if (unresolvedMismatchCount !== report.unresolvedMismatchCount
      || (report.state === 'complete') !== (unresolvedMismatchCount === 0)) {
      fail('m4_reconciliation_report_invalid');
    }
    const bindingPayload = {
      schema: report.schema,
      dimensions: [...M4_DIMENSIONS],
      dimensionEvidence,
      unresolvedMismatchCount,
      completeness: 1,
      tolerance: 0,
      state: report.state,
      mismatchSamples,
    };
    const bindingDigest = digest(bindingPayload);
    const dimensionsBinding = validateCheckpoint(report.dimensionsBinding);
    if (dimensionsBinding.id !== `m4-binding-${bindingDigest.slice('sha256:'.length)}`
      || dimensionsBinding.digest !== bindingDigest) fail('m4_reconciliation_report_invalid');
    return { ...bindingPayload, dimensionsBinding };
  } catch (error) {
    if (error?.code === 'm4_reconciliation_report_invalid') throw error;
    fail('m4_reconciliation_report_invalid');
  }
}
