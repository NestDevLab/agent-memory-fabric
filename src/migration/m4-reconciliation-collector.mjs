import crypto from 'node:crypto';

import { canonicalJson } from '../ingest/transcripts/canonical.mjs';
import {
  createM4ReconciliationArchiveRevision,
  createM4ReconciliationEventAccumulator,
  createM4ReconciliationSnapshot,
  m4ReconciliationArchiveRevisionEvidence,
  M4_RECONCILIATION_SNAPSHOT_MAX_EVENTS,
  verifyM4ReconciliationArchiveRevision,
  verifyM4ReconciliationSnapshot,
} from './m4-reconciliation-snapshot.mjs';

const ID = /^[a-z][a-z0-9-]{2,79}$/;
const EVENT_ID = /^cevt_[a-z0-9][a-z0-9_-]{7,127}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const STATES = new Set(['active', 'edited', 'replacement', 'tombstone', 'conflict']);

function fail(code) { const error = new Error(code); error.code = code; throw error; }
function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function exact(value, keys) { return plain(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)); }
function clone(value, code) { try { return structuredClone(value); } catch { fail(code); } }
function digest(value) { return `sha256:${crypto.createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`; }
function checkpoint(value, code) { if (!exact(value, ['id', 'digest']) || typeof value.id !== 'string' || !ID.test(value.id) || typeof value.digest !== 'string' || !DIGEST.test(value.digest)) fail(code); return { id: value.id, digest: value.digest }; }
function timestamp(value, code) { if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(value) || !Number.isFinite(Date.parse(value)) || new Date(Date.parse(value)).toISOString().slice(0, 19) !== value.slice(0, 19)) fail(code); return value; }
function key(value, code) {
  if (!exact(value, ['schema', 'keyId', 'key']) || value.schema !== 'amf.migration-signing-key/v1' || typeof value.keyId !== 'string' || !ID.test(value.keyId) || typeof value.key !== 'string' || !BASE64.test(value.key)) fail(code);
  const bytes = Buffer.from(value.key, 'base64');
  if (bytes.length < 32 || bytes.length > 64 || bytes.toString('base64') !== value.key) { bytes.fill(0); fail(code); }
  return { keyId: value.keyId, bytes };
}
function independent(documents, code) {
  const loaded = documents.map(item => key(item, code));
  try { for (let left = 0; left < loaded.length; left += 1) for (let right = left + 1; right < loaded.length; right += 1) {
    const a = Buffer.alloc(64); const b = Buffer.alloc(64); loaded[left].bytes.copy(a); loaded[right].bytes.copy(b);
    const equivalent = loaded[left].keyId === loaded[right].keyId || crypto.timingSafeEqual(a, b); a.fill(0); b.fill(0);
    if (equivalent) fail(code);
  } } finally { loaded.forEach(item => item.bytes.fill(0)); }
}
export function assertM4ReconciliationCollectorKeySeparation(documents) {
  if (!Array.isArray(documents) || documents.length < 2 || documents.length > 8) {
    fail('m4_reconciliation_collector_key_separation_invalid');
  }
  independent(documents, 'm4_reconciliation_collector_key_separation_invalid');
}
function completion(value, code) {
  if (!plain(value) || value.state !== 'complete' || !Object.hasOwn(value, 'checkpoint')) fail(code);
  const safe = clone(value, code); safe.checkpoint = checkpoint(safe.checkpoint, code); return safe;
}
function project(value, code) {
  const payloadDigest = plain(value?.integrity) ? value.integrity.payloadDigest : value?.payloadDigest;
  if (!plain(value) || typeof value.eventId !== 'string' || !EVENT_ID.test(value.eventId) || typeof payloadDigest !== 'string' || !DIGEST.test(payloadDigest) || typeof value.logicalDigest !== 'string' || !DIGEST.test(value.logicalDigest) || !STATES.has(value.state)) fail(code);
  const output = { eventId: value.eventId, payloadDigest, logicalDigest: value.logicalDigest, sourceOccurredAt: timestamp(value.sourceOccurredAt, code), occurredAt: timestamp(value.occurredAt, code), state: value.state };
  if (value.state === 'edited' || value.state === 'replacement') { if (typeof value.replacesEventId !== 'string' || !EVENT_ID.test(value.replacesEventId)) fail(code); output.replacesEventId = value.replacesEventId; }
  if (value.state === 'tombstone') { if (typeof value.tombstonesEventId !== 'string' || !EVENT_ID.test(value.tombstonesEventId)) fail(code); output.tombstonesEventId = value.tombstonesEventId; }
  if (value.state === 'conflict') { if (!Array.isArray(value.conflictsWithEventIds) || value.conflictsWithEventIds.length < 1 || value.conflictsWithEventIds.length > 32 || value.conflictsWithEventIds.some((id, index, ids) => typeof id !== 'string' || !EVENT_ID.test(id) || (index > 0 && ids[index - 1] >= id))) fail(code); output.conflictsWithEventIds = [...value.conflictsWithEventIds]; }
  return output;
}
function staticEvidence(value, code) {
  if (!exact(value, ['pausedInterval', 'replayQueues', 'sourceCheckpoints'])) fail(code);
  const map = (item, names) => { if (!exact(item, names)) fail(code); return Object.fromEntries(names.map(name => [name, checkpoint(item[name], code)])); };
  return { pausedInterval: map(value.pausedInterval, ['start', 'end']), replayQueues: map(value.replayQueues, ['pendingOutbox', 'acknowledgements', 'deadLetters']), sourceCheckpoints: map(value.sourceCheckpoints, ['collectorCursor', 'sourceCheckpoint', 'nativeTranscriptAuthority']) };
}

export async function collectM4ReconciliationArchiveRevision(input = {}) {
  const code = 'm4_reconciliation_collector_revision_invalid';
  if (!exact(input, ['archive', 'manifestId', 'revisionSource', 'revisionKeyDocument', 'observedAt', 'validThrough']) || !['legacy-v2', 'v3'].includes(input.archive) || typeof input.manifestId !== 'string' || !ID.test(input.manifestId) || typeof input.revisionSource !== 'function') fail(code);
  let source; try { source = completion(await input.revisionSource(), code); } catch { fail('m4_reconciliation_collector_revision_source_unverified'); }
  try {
    const revision = createM4ReconciliationArchiveRevision({ manifestId: input.manifestId, archive: input.archive, revision: source.checkpoint, observedAt: timestamp(input.observedAt, code), validThrough: timestamp(input.validThrough, code) }, input.revisionKeyDocument);
    return clone(verifyM4ReconciliationArchiveRevision(revision, input.revisionKeyDocument), code);
  } catch { fail(code); }
}

export async function collectM4ReconciliationSnapshot(input = {}) {
  const code = 'm4_reconciliation_collector_snapshot_invalid';
  const names = ['archive', 'snapshotId', 'completion', 'completionKeyDocument', 'verifyCompletion', 'revisionManifest', 'revisionKeyDocument', 'snapshotKeyDocument', 'events', 'spool', 'staticEvidence', 'capturedAt'];
  if (!exact(input, names) || !['legacy-v2', 'v3'].includes(input.archive) || typeof input.snapshotId !== 'string' || !ID.test(input.snapshotId) || typeof input.verifyCompletion !== 'function' || typeof input.events?.[Symbol.asyncIterator] !== 'function' || !exact(input.spool, ['append', 'finish', 'publish', 'abort']) || Object.values(input.spool).some(method => typeof method !== 'function')) fail(code);
  let verifiedCompletion; let revision;
  try { verifiedCompletion = completion(await input.verifyCompletion(clone(input.completion, code), clone(input.completionKeyDocument, code)), code); }
  catch { fail('m4_reconciliation_collector_completion_unverified'); }
  assertM4ReconciliationCollectorKeySeparation([input.completionKeyDocument,
    input.revisionKeyDocument, input.snapshotKeyDocument]);
  try { revision = verifyM4ReconciliationArchiveRevision(clone(input.revisionManifest, code), input.revisionKeyDocument); }
  catch { fail('m4_reconciliation_collector_revision_unverified'); }
  if (revision.archive !== input.archive) fail('m4_reconciliation_collector_revision_linkage_invalid');
  const evidence = staticEvidence(clone(input.staticEvidence, code), code); const accumulator = createM4ReconciliationEventAccumulator(); const eventFile = crypto.createHash('sha256');
  try {
    for await (const fullEvent of input.events) {
      const projected = project(fullEvent, 'm4_reconciliation_collector_event_invalid');
      accumulator.add(projected); eventFile.update(`${canonicalJson(projected)}\n`, 'utf8'); await input.spool.append(clone(projected, code));
    }
    const set = accumulator.finish(); const finished = await input.spool.finish();
    const expectedFileDigest = `sha256:${eventFile.digest('hex')}`;
    if (!exact(finished, ['eventsPath', 'eventFileDigest', 'eventCount', 'eventSetDigest']) || typeof finished.eventsPath !== 'string' || !finished.eventsPath.startsWith('/') || typeof finished.eventFileDigest !== 'string' || !DIGEST.test(finished.eventFileDigest) || finished.eventCount !== set.eventCount || finished.eventSetDigest !== set.eventSetDigest || finished.eventFileDigest !== expectedFileDigest) fail('m4_reconciliation_collector_spool_attestation_invalid');
    const snapshot = createM4ReconciliationSnapshot({ snapshotId: input.snapshotId, archive: input.archive, revision: revision.revision, terminalCheckpoint: verifiedCompletion.checkpoint, capturedAt: timestamp(input.capturedAt, code), revisionEvidence: m4ReconciliationArchiveRevisionEvidence(revision), prerequisiteEvidenceDigest: digest(verifiedCompletion), ...set, eventFileDigest: finished.eventFileDigest, staticEvidenceDigest: digest(evidence) }, input.snapshotKeyDocument);
    const verifiedSnapshot = verifyM4ReconciliationSnapshot(snapshot, input.snapshotKeyDocument);
    const published = await input.spool.publish({ revision: clone(revision, code), snapshot: clone(verifiedSnapshot, code) });
    if (!exact(published, ['eventsPath', 'revisionPath', 'snapshotPath', 'completionPath'])
      || Object.values(published).some(target => typeof target !== 'string' || !target.startsWith('/'))
      || published.eventsPath === finished.eventsPath) fail('m4_reconciliation_collector_publication_invalid');
    return { revision: clone(revision, code), snapshot: clone(verifiedSnapshot, code), ...clone(published, code) };
  } catch (error) {
    try { await input.spool.abort(); } catch {}
    if (error?.code?.startsWith?.('m4_reconciliation_')) throw error;
    fail('m4_reconciliation_collector_spool_failed');
  }
}
