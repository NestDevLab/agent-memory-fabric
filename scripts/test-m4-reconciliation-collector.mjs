import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import { canonicalJson } from '../src/ingest/transcripts/canonical.mjs';
import { createM4ReconciliationEventAccumulator } from '../src/migration/m4-reconciliation-snapshot.mjs';
import { collectM4ReconciliationArchiveRevision, collectM4ReconciliationSnapshot } from '../src/migration/m4-reconciliation-collector.mjs';

const sha = value => `sha256:${crypto.createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`;
const bytesDigest = value => `sha256:${crypto.createHash('sha256').update(value, 'utf8').digest('hex')}`;
const key = (keyId, byte) => ({ schema: 'amf.migration-signing-key/v1', keyId, key: Buffer.alloc(32, byte).toString('base64') });
const cp = (id, marker = id) => ({ id, digest: sha(marker) });
const completion = checkpoint => ({ state: 'complete', checkpoint });
const evidence = () => ({ pausedInterval: { start: cp('pause-start'), end: cp('pause-end') }, replayQueues: { pendingOutbox: cp('pending-outbox'), acknowledgements: cp('acknowledgements'), deadLetters: cp('dead-letters') }, sourceCheckpoints: { collectorCursor: cp('collector-cursor'), sourceCheckpoint: cp('source-checkpoint'), nativeTranscriptAuthority: cp('native-authority') } });
const event = (number, state = 'active') => {
  const base = { eventId: `cevt_test${String(number).padStart(4, '0')}`, visibleText: 'private source text', logicalDigest: sha(`logical-${number}`), integrity: { payloadDigest: sha(`payload-${number}`) }, sourceOccurredAt: '2026-07-22T00:00:00Z', occurredAt: '2026-07-22T00:00:01Z', state };
  if (state === 'edited' || state === 'replacement') base.replacesEventId = 'cevt_test0000';
  if (state === 'tombstone') base.tombstonesEventId = 'cevt_test0000';
  if (state === 'conflict') base.conflictsWithEventIds = ['cevt_test0000'];
  return base;
};
async function* source(rows, seen) { seen.value = true; yield* rows; }
function spool() {
  const rows = []; let aborted = false;
  return { object: { async append(row) { rows.push(row); }, async finish() { const a = createM4ReconciliationEventAccumulator(); rows.forEach(row => a.add(row)); const set = a.finish(); return { eventsPath: '/private/staging/events.jsonl', eventFileDigest: bytesDigest(rows.map(row => `${canonicalJson(row)}\n`).join('')), ...set }; }, async publish() { return { eventsPath: '/private/final/events.jsonl', revisionPath: '/private/final/revision.json', snapshotPath: '/private/final/snapshot.json', completionPath: '/private/final/complete.json' }; }, async abort() { aborted = true; } }, rows, get aborted() { return aborted; } };
}
async function fixture(rows = [event(1)]) {
  const completionKey = key('completion-key', 1); const revisionKey = key('revision-key', 2); const snapshotKey = key('snapshot-key', 3); const terminal = cp('terminal-checkpoint');
  const revision = await collectM4ReconciliationArchiveRevision({ archive: 'v3', manifestId: 'collector-revision', revisionSource: async () => completion(cp('content-revision')), revisionKeyDocument: revisionKey, observedAt: '2026-07-22T00:00:00Z', validThrough: '2026-07-23T00:00:00Z' });
  const sink = spool(); const seen = { value: false };
  return { completionKey, revisionKey, snapshotKey, terminal, revision, sink, seen, input: { archive: 'v3', snapshotId: 'collector-snapshot', completion: completion(terminal), completionKeyDocument: completionKey, verifyCompletion: async value => completion(value.checkpoint), revisionManifest: revision, revisionKeyDocument: revisionKey, snapshotKeyDocument: snapshotKey, events: source(rows, seen), spool: sink.object, staticEvidence: evidence(), capturedAt: '2026-07-22T00:01:00Z' } };
}

test('revision derives only from the complete source checkpoint', async () => {
  const revision = await collectM4ReconciliationArchiveRevision({ archive: 'legacy-v2', manifestId: 'legacy-revision', revisionSource: async () => completion(cp('source-terminal')), revisionKeyDocument: key('archive-key', 9), observedAt: '2026-07-22T00:00:00Z', validThrough: '2026-07-23T00:00:00Z' });
  assert.equal(revision.revision.id, 'source-terminal');
  await assert.rejects(() => collectM4ReconciliationArchiveRevision({ archive: 'v3', manifestId: 'bad-revision', revisionSource: async () => ({ checkpoint: cp('source-terminal') }), revisionKeyDocument: key('archive-key', 9), observedAt: '2026-07-22T00:00:00Z', validThrough: '2026-07-23T00:00:00Z' }), { code: 'm4_reconciliation_collector_revision_source_unverified' });
});

test('collector verifies prerequisites before source access and projects all relationship states without content', async () => {
  const compact = event(1); compact.payloadDigest = compact.integrity.payloadDigest; delete compact.integrity;
  const item = await fixture([compact, event(2, 'edited'), event(3, 'replacement'), event(4, 'tombstone'), event(5, 'conflict')]);
  item.input.completion = { schema: 'signed-completion/v1', state: 'complete', checkpoint: item.terminal,
    evidence: { digest: sha('completion') } };
  item.input.verifyCompletion = async value => value;
  const output = await collectM4ReconciliationSnapshot(item.input);
  assert.equal(item.seen.value, true); assert.equal(output.snapshot.eventCount, 5); assert.equal(item.sink.rows[0].visibleText, undefined);
  assert.notDeepEqual(output.snapshot.revision, output.snapshot.terminalCheckpoint);
  assert.equal(JSON.stringify(output).includes('private source text'), false); assert.equal(Object.keys(item.sink.rows[4]).includes('conflictsWithEventIds'), true);
});

test('wrong revision, equivalent HMAC keys, bad order and bad spool attestations fail closed', async () => {
  const stale = await fixture(); stale.input.revisionManifest = { ...stale.revision, revision: cp('other-terminal') };
  await assert.rejects(() => collectM4ReconciliationSnapshot(stale.input), { code: 'm4_reconciliation_collector_revision_unverified' }); assert.equal(stale.seen.value, false);
  const same = await fixture(); same.input.snapshotKeyDocument = { ...same.input.snapshotKeyDocument, keyId: 'other-key', key: same.input.revisionKeyDocument.key };
  await assert.rejects(() => collectM4ReconciliationSnapshot(same.input), { code: 'm4_reconciliation_collector_key_separation_invalid' }); assert.equal(same.seen.value, false);
  const padded = await fixture(); padded.input.snapshotKeyDocument = { ...padded.input.snapshotKeyDocument,
    keyId: 'padded-key', key: Buffer.concat([Buffer.alloc(32, 2), Buffer.alloc(32)]).toString('base64') };
  await assert.rejects(() => collectM4ReconciliationSnapshot(padded.input),
    { code: 'm4_reconciliation_collector_key_separation_invalid' }); assert.equal(padded.seen.value, false);
  const unordered = await fixture([event(2), event(1)]); await assert.rejects(() => collectM4ReconciliationSnapshot(unordered.input), { code: 'm4_reconciliation_snapshot_event_order_invalid' }); assert.equal(unordered.sink.aborted, true);
  const bad = await fixture(); bad.input.spool = { ...bad.sink.object, async finish() { return { eventsPath: '/private/staging/events.jsonl', eventFileDigest: sha('x'), eventCount: 0, eventSetDigest: sha('x') }; } };
  await assert.rejects(() => collectM4ReconciliationSnapshot(bad.input), { code: 'm4_reconciliation_collector_spool_attestation_invalid' });
});
