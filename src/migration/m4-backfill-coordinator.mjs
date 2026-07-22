import crypto from 'node:crypto';

import { canonicalJson } from '../ingest/transcripts/canonical.mjs';
import { isConversationEventUtcTimestamp } from '../conversation-event-v3.mjs';

export const M4_BACKFILL_MAX_EVENTS = 1_000;

const GATE_SCHEMA = 'amf.m4-backfill-gate/v1';
const PLAN_SCHEMA = 'amf.m4-backfill-plan/v1';
const PROGRESS_SCHEMA = 'amf.m4-backfill-progress/v1';
const PROGRESS_ACK_SCHEMA = 'amf.m4-backfill-progress-ack/v1';
const RESULT_SCHEMA = 'amf.m4-backfill-result/v1';
const ID_PATTERN = /^[a-z][a-z0-9-]{2,79}$/;
const EVENT_ID_PATTERN = /^cevt_[a-z0-9][a-z0-9_-]{7,127}$/;
const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/;
const SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{43,86}$/;
const PHASES = new Set(['v2-archive', 'paused-native']);

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype;
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasExactKeys(value, keys) {
  return isPlainObject(value)
    && Object.keys(value).length === keys.length
    && keys.every(key => Object.hasOwn(value, key));
}

function copyCheckpoint(value, code) {
  if (!hasExactKeys(value, ['id', 'digest'])
    || typeof value.id !== 'string'
    || !ID_PATTERN.test(value.id)
    || typeof value.digest !== 'string'
    || !DIGEST_PATTERN.test(value.digest)) {
    fail(code);
  }
  return { id: value.id, digest: value.digest };
}

function copySignedEvidence(value, code) {
  if (!hasExactKeys(value, ['manifestId', 'digest', 'signature'])
    || typeof value.manifestId !== 'string'
    || !ID_PATTERN.test(value.manifestId)
    || typeof value.digest !== 'string'
    || !DIGEST_PATTERN.test(value.digest)
    || typeof value.signature !== 'string'
    || !SIGNATURE_PATTERN.test(value.signature)) {
    fail(code);
  }
  return {
    manifestId: value.manifestId,
    digest: value.digest,
    signature: value.signature,
  };
}

function copyGate(value) {
  const keys = [
    'schema', 'state', 'runId', 'phase', 'pauseEvidence', 'rollbackEvidence',
    'sourceCheckpoint', 'targetCheckpoint',
  ];
  if (!hasExactKeys(value, keys)
    || value.schema !== GATE_SCHEMA
    || value.state !== 'approved'
    || typeof value.runId !== 'string'
    || !ID_PATTERN.test(value.runId)
    || typeof value.phase !== 'string'
    || !PHASES.has(value.phase)) {
    fail('m4_backfill_gate_invalid');
  }
  return {
    schema: GATE_SCHEMA,
    state: 'approved',
    runId: value.runId,
    phase: value.phase,
    pauseEvidence: copySignedEvidence(value.pauseEvidence, 'm4_backfill_gate_invalid'),
    rollbackEvidence: copySignedEvidence(value.rollbackEvidence, 'm4_backfill_gate_invalid'),
    sourceCheckpoint: copyCheckpoint(value.sourceCheckpoint, 'm4_backfill_gate_invalid'),
    targetCheckpoint: copyCheckpoint(value.targetCheckpoint, 'm4_backfill_gate_invalid'),
  };
}

function validateMaxEvents(maxEvents) {
  if (!Number.isSafeInteger(maxEvents) || maxEvents < 1 || maxEvents > M4_BACKFILL_MAX_EVENTS) {
    fail('m4_backfill_request_invalid');
  }
  return maxEvents;
}

function sha256(value) {
  return `sha256:${crypto.createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`;
}

function planPayload(gate, maxEvents) {
  return {
    schema: PLAN_SCHEMA,
    runId: gate.runId,
    phase: gate.phase,
    pauseEvidence: gate.pauseEvidence,
    rollbackEvidence: gate.rollbackEvidence,
    sourceCheckpoint: gate.sourceCheckpoint,
    targetCheckpoint: gate.targetCheckpoint,
    maxEvents,
  };
}

async function verifiedGate(gateVerifier) {
  if (typeof gateVerifier !== 'function') fail('m4_backfill_gate_verifier_required');
  let value;
  try {
    value = await gateVerifier();
  } catch {
    fail('m4_backfill_gate_unavailable');
  }
  return copyGate(value);
}

export async function planM4BackfillBatch({ gateVerifier, maxEvents } = {}) {
  const gate = await verifiedGate(gateVerifier);
  const safeMaxEvents = validateMaxEvents(maxEvents);
  const payload = planPayload(gate, safeMaxEvents);
  return {
    ...payload,
    planDigest: sha256(payload),
  };
}

function validateDependencies({ lease, source, outbox, sink, checkpointStore, postCutoffStore }, phase) {
  if (!isObject(lease)
    || typeof lease.acquire !== 'function'
    || typeof lease.heartbeat !== 'function'
    || typeof lease.release !== 'function'
    || !isObject(source)
    || typeof source.open !== 'function'
    || !isObject(outbox)
    || typeof outbox.enqueue !== 'function'
    || typeof outbox.deliver !== 'function'
    || !isObject(sink)
    || typeof sink.deliver !== 'function'
    || !isObject(checkpointStore)
    || typeof checkpointStore.load !== 'function'
    || typeof checkpointStore.commit !== 'function'
    || (phase === 'paused-native' && (!isObject(postCutoffStore) || typeof postCutoffStore.load !== 'function' || typeof postCutoffStore.commit !== 'function'))
    || (phase === 'v2-archive' && postCutoffStore !== null)) {
    fail('m4_backfill_dependency_invalid');
  }
}

function copyProgress(value, plan) {
  if (value === null) return null;
  const keys = ['schema', 'runId', 'phase', 'planDigest', 'sequence', 'checkpoint', 'eventId', 'payloadDigest'];
  if (!hasExactKeys(value, keys)
    || value.schema !== PROGRESS_SCHEMA
    || value.runId !== plan.runId
    || value.phase !== plan.phase
    || value.planDigest !== plan.planDigest
    || !Number.isSafeInteger(value.sequence)
    || value.sequence < 1
    || typeof value.eventId !== 'string'
    || !EVENT_ID_PATTERN.test(value.eventId)
    || typeof value.payloadDigest !== 'string'
    || !DIGEST_PATTERN.test(value.payloadDigest)) {
    fail('m4_backfill_progress_invalid');
  }
  return {
    schema: PROGRESS_SCHEMA,
    runId: value.runId,
    phase: value.phase,
    planDigest: value.planDigest,
    sequence: value.sequence,
    checkpoint: copyCheckpoint(value.checkpoint, 'm4_backfill_progress_invalid'),
    eventId: value.eventId,
    payloadDigest: value.payloadDigest,
  };
}

function validateAsyncIterator(value) {
  if (value === null || typeof value !== 'object' || typeof value.next !== 'function') {
    fail('m4_backfill_source_invalid');
  }
  return value;
}

function sourceIterator(value) {
  try {
    if (!isObject(value) || typeof value[Symbol.asyncIterator] !== 'function') {
      fail('m4_backfill_source_invalid');
    }
    return validateAsyncIterator(value[Symbol.asyncIterator]());
  } catch {
    fail('m4_backfill_source_invalid');
  }
}

function copyPostCutoffBinding(value, phase) {
  if (phase === 'v2-archive') { if (value !== null && value !== undefined) fail('m4_backfill_post_cutoff_binding_invalid'); return null; }
  if (value === null || value === undefined) return null;
  if (!hasExactKeys(value, ['legacyEventId', 'legacySessionId', 'eventId', 'conversationId', 'sourceInstanceId', 'sourceTags', 'observedAt'])
    || typeof value.legacyEventId !== 'string' || !/^evt_[a-f0-9]{64}$/.test(value.legacyEventId)
    || typeof value.legacySessionId !== 'string' || !/^ses_[a-f0-9]{64}$/.test(value.legacySessionId)
    || typeof value.eventId !== 'string' || !EVENT_ID_PATTERN.test(value.eventId)
    || typeof value.conversationId !== 'string' || !/^ccon_[a-z0-9][a-z0-9_-]{7,127}$/.test(value.conversationId)
    || typeof value.sourceInstanceId !== 'string' || !/^src_[a-z0-9][a-z0-9_-]{7,127}$/.test(value.sourceInstanceId)
    || !Array.isArray(value.sourceTags) || value.sourceTags.length < 1 || value.sourceTags.length > 64
    || value.sourceTags.some(tag => typeof tag !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}:[a-f0-9]{64}$/.test(tag))
    || new Set(value.sourceTags).size !== value.sourceTags.length || value.sourceTags.some((tag, i) => i > 0 && value.sourceTags[i - 1] >= tag)
    || !isConversationEventUtcTimestamp(value.observedAt)) fail('m4_backfill_post_cutoff_binding_invalid');
  return structuredClone(value);
}

function copyRow(value, previousSequence, previousCheckpoint, phase) {
  const allowed = phase === 'v2-archive' ? ['sequence', 'checkpoint', 'event'] : ['sequence', 'checkpoint', 'event', 'postCutoffBinding'];
  if (!hasExactKeys(value, allowed)
    || !Number.isSafeInteger(value.sequence)
    || value.sequence < 1
    || value.sequence <= previousSequence
    || value.event === undefined) {
    fail('m4_backfill_row_invalid');
  }
  const checkpoint = copyCheckpoint(value.checkpoint, 'm4_backfill_row_invalid');
  if (canonicalJson(checkpoint) === canonicalJson(previousCheckpoint)
    || !isPlainObject(value.event)
    || typeof value.event.eventId !== 'string'
    || !EVENT_ID_PATTERN.test(value.event.eventId)
    || !isPlainObject(value.event.integrity)
    || typeof value.event.integrity.payloadDigest !== 'string'
    || !DIGEST_PATTERN.test(value.event.integrity.payloadDigest)) {
    fail('m4_backfill_row_invalid');
  }
  return {
    sequence: value.sequence,
    checkpoint,
    event: value.event,
    postCutoffBinding: copyPostCutoffBinding(value.postCutoffBinding, phase), eventMetadata: {
      eventId: value.event.eventId,
      payloadDigest: value.event.integrity.payloadDigest,
    },
  };
}

function copyQueueReceipt(value, eventMetadata) {
  if (!hasExactKeys(value, ['eventId', 'payloadDigest', 'state', 'duplicate'])
    || value.eventId !== eventMetadata.eventId
    || value.payloadDigest !== eventMetadata.payloadDigest
    || !['pending', 'acknowledged'].includes(value.state)
    || typeof value.duplicate !== 'boolean') {
    fail('m4_backfill_enqueue_invalid');
  }
  return {
    eventId: value.eventId,
    payloadDigest: value.payloadDigest,
    state: value.state,
    duplicate: value.duplicate,
  };
}

function copyAcknowledgement(value, queued) {
  if (!hasExactKeys(value, ['eventId', 'payloadDigest', 'state', 'duplicate'])
    || value.eventId !== queued.eventId
    || value.payloadDigest !== queued.payloadDigest
    || value.state !== 'acknowledged'
    || typeof value.duplicate !== 'boolean') {
    fail('m4_backfill_ack_invalid');
  }
  return {
    eventId: value.eventId,
    payloadDigest: value.payloadDigest,
    state: 'acknowledged',
    duplicate: value.duplicate,
  };
}

function nextProgress(plan, row, acknowledgement) {
  return {
    schema: PROGRESS_SCHEMA,
    runId: plan.runId,
    phase: plan.phase,
    planDigest: plan.planDigest,
    sequence: row.sequence,
    checkpoint: row.checkpoint,
    eventId: acknowledgement.eventId,
    payloadDigest: acknowledgement.payloadDigest,
  };
}

function copyProgressAcknowledgement(value, progress) {
  const keys = ['schema', 'committed', 'runId', 'phase', 'planDigest', 'sequence', 'checkpoint'];
  if (!hasExactKeys(value, keys)
    || value.schema !== PROGRESS_ACK_SCHEMA
    || value.committed !== true
    || value.runId !== progress.runId
    || value.phase !== progress.phase
    || value.planDigest !== progress.planDigest
    || value.sequence !== progress.sequence) {
    fail('m4_backfill_checkpoint_ack_invalid');
  }
  const checkpoint = copyCheckpoint(value.checkpoint, 'm4_backfill_checkpoint_ack_invalid');
  if (canonicalJson(checkpoint) !== canonicalJson(progress.checkpoint)) {
    fail('m4_backfill_checkpoint_ack_invalid');
  }
  return {
    schema: PROGRESS_ACK_SCHEMA,
    committed: true,
    runId: progress.runId,
    phase: progress.phase,
    planDigest: progress.planDigest,
    sequence: progress.sequence,
    checkpoint,
  };
}

async function closeIterator(iterator) {
  if (iterator === null) return null;
  try {
    await iterator.return?.();
    return null;
  } catch {
    return true;
  }
}

async function call(operation, code) {
  try {
    return await operation();
  } catch {
    fail(code);
  }
}

export async function runM4BackfillBatch({
  gateVerifier,
  maxEvents,
  confirmedPlanDigest,
  lease,
  source,
  outbox,
  sink,
  checkpointStore,
  postCutoffStore = null,
} = {}) {
  const plan = await planM4BackfillBatch({ gateVerifier, maxEvents });
  if (typeof confirmedPlanDigest !== 'string' || confirmedPlanDigest !== plan.planDigest) {
    fail('m4_backfill_plan_confirmation_invalid');
  }
  validateDependencies({ lease, source, outbox, sink, checkpointStore, postCutoffStore }, plan.phase);

  let acquired = false;
  let iterator = null;
  let primaryError = null;
  try {
    await call(() => lease.acquire({ runId: plan.runId, phase: plan.phase }), 'm4_backfill_lease_acquire_failed');
    acquired = true;
    const loaded = copyProgress(await call(
      () => checkpointStore.load({ runId: plan.runId, phase: plan.phase }),
      'm4_backfill_checkpoint_load_failed',
    ), plan);
    const after = copyCheckpoint(
      loaded === null ? plan.sourceCheckpoint : loaded.checkpoint,
      'm4_backfill_progress_invalid',
    );
    const opened = await call(
      () => source.open({
        runId: plan.runId,
        phase: plan.phase,
        after: copyCheckpoint(after, 'm4_backfill_progress_invalid'),
        afterSequence: loaded?.sequence ?? 0,
        maxEvents: plan.maxEvents,
      }),
      'm4_backfill_source_open_failed',
    );
    iterator = sourceIterator(opened);

    let processed = 0;
    let duplicates = 0;
    let previousSequence = loaded?.sequence ?? 0;
    let lastCheckpoint = copyCheckpoint(after, 'm4_backfill_progress_invalid');
    let exhausted = false;

    while (processed < plan.maxEvents) {
      const next = await call(() => iterator.next(), 'm4_backfill_source_read_failed');
      if (!isPlainObject(next) || typeof next.done !== 'boolean') fail('m4_backfill_source_invalid');
      if (next.done) {
        exhausted = true;
        break;
      }
      const row = copyRow(next.value, previousSequence, lastCheckpoint, plan.phase);
      await call(() => lease.heartbeat({ runId: plan.runId, phase: plan.phase }), 'm4_backfill_lease_heartbeat_failed');
      const queued = copyQueueReceipt(await call(
        () => outbox.enqueue(row.event),
        'm4_backfill_enqueue_failed',
      ), row.eventMetadata);
      const acknowledgement = copyAcknowledgement(await call(
        () => outbox.deliver(queued.eventId, sink),
        'm4_backfill_delivery_failed',
      ), queued);
      if (row.postCutoffBinding !== null) {
        const committed = await call(() => postCutoffStore.commit(row.postCutoffBinding), 'm4_backfill_post_cutoff_commit_failed');
        if (canonicalJson(committed) !== canonicalJson(row.postCutoffBinding)) fail('m4_backfill_post_cutoff_ack_invalid');
      }
      const progress = nextProgress(plan, row, acknowledgement);
      const commitInput = copyProgress(progress, plan);
      const commitAcknowledgement = await call(
        () => checkpointStore.commit(commitInput),
        'm4_backfill_checkpoint_commit_failed',
      );
      copyProgressAcknowledgement(commitAcknowledgement, progress);
      processed += 1;
      if (acknowledgement.duplicate) duplicates += 1;
      previousSequence = row.sequence;
      lastCheckpoint = copyCheckpoint(row.checkpoint, 'm4_backfill_row_invalid');
    }

    if (!exhausted && processed === plan.maxEvents) {
      const extra = await call(() => iterator.next(), 'm4_backfill_source_read_failed');
      if (!isPlainObject(extra) || typeof extra.done !== 'boolean') fail('m4_backfill_source_invalid');
      exhausted = extra.done;
    }
    return {
      schema: RESULT_SCHEMA,
      runId: plan.runId,
      phase: plan.phase,
      processed,
      duplicates,
      lastCheckpoint,
      complete: exhausted,
    };
  } catch (error) {
    primaryError = error;
    throw error;
  } finally {
    const closeFailure = await closeIterator(iterator);
    let releaseFailure = false;
    if (acquired) {
      try {
        await lease.release({ runId: plan.runId, phase: plan.phase });
      } catch {
        releaseFailure = true;
      }
    }
    if (primaryError === null) {
      if (closeFailure) fail('m4_backfill_source_close_failed');
      if (releaseFailure) fail('m4_backfill_lease_release_failed');
    }
  }
}
