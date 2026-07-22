import assert from 'node:assert/strict';
import test from 'node:test';

import {
  createM4ReconciliationArchiveRevision,
  createM4ReconciliationEventAccumulator,
  createM4ReconciliationSnapshot,
  m4ReconciliationArchiveRevisionEvidence,
  verifyM4ReconciliationArchiveRevision,
  verifyM4ReconciliationSnapshot,
} from '../src/migration/m4-reconciliation-snapshot.mjs';

const digest = character => `sha256:${character.repeat(64)}`;
const checkpoint = (id, character) => ({ id, digest: digest(character) });
const key = (keyId, byte) => ({ schema: 'amf.migration-signing-key/v1', keyId,
  key: Buffer.alloc(32, byte).toString('base64') });
const event = number => ({ eventId: `cevt_snapshot${String(number).padStart(4, '0')}`,
  payloadDigest: digest(String(number)), logicalDigest: digest('a'), sourceOccurredAt: '2026-01-01T00:00:00Z',
  occurredAt: '2026-01-01T00:00:01Z', state: 'active' });

function fixture() {
  const accumulator = createM4ReconciliationEventAccumulator(); accumulator.add(event(1)); accumulator.add(event(2));
  const revisionKey = key('snapshot-revision-authority-key', 2);
  const revision = createM4ReconciliationArchiveRevision({ manifestId: 'snapshot-revision-one', archive: 'legacy-v2',
    revision: checkpoint('snapshot-revision', 'b'), observedAt: '2026-01-01T00:00:00Z',
    validThrough: '2026-01-02T00:00:00Z' }, revisionKey);
  return createM4ReconciliationSnapshot({ snapshotId: 'snapshot-manifest-one', archive: 'legacy-v2',
    revision: revision.revision, terminalCheckpoint: checkpoint('snapshot-terminal', 'c'),
    capturedAt: '2026-01-01T01:00:00Z', revisionEvidence: m4ReconciliationArchiveRevisionEvidence(revision),
    prerequisiteEvidenceDigest: digest('f'), ...accumulator.finish(), eventFileDigest: digest('d'),
    staticEvidenceDigest: digest('e') }, key('snapshot-authority-key', 1));
}

test('archive revision authority binds a bounded current revision window', () => {
  const signingKey = key('snapshot-revision-authority-key', 2);
  const revision = createM4ReconciliationArchiveRevision({ manifestId: 'snapshot-revision-one', archive: 'v3',
    revision: checkpoint('snapshot-revision', 'b'), observedAt: '2026-01-01T00:00:00Z',
    validThrough: '2026-01-02T00:00:00Z' }, signingKey);
  assert.deepEqual(verifyM4ReconciliationArchiveRevision(revision, signingKey), revision);
  assert.doesNotThrow(() => createM4ReconciliationArchiveRevision({
    manifestId: 'snapshot-revision-seven-days', archive: 'v3',
    revision: checkpoint('snapshot-revision', 'b'), observedAt: '2026-01-01T00:00:00Z',
    validThrough: '2026-01-08T00:00:00Z' }, signingKey));
  assert.throws(() => createM4ReconciliationArchiveRevision({
    manifestId: 'snapshot-revision-seven-days-plus', archive: 'v3',
    revision: checkpoint('snapshot-revision', 'b'), observedAt: '2026-01-01T00:00:00Z',
    validThrough: '2026-01-08T00:00:00.000000001Z' }, signingKey));
  assert.throws(() => createM4ReconciliationArchiveRevision({ manifestId: 'snapshot-revision-one', archive: 'v3',
    revision: checkpoint('snapshot-revision', 'b'), observedAt: '2026-01-01T00:00:00Z',
    validThrough: '2026-01-09T00:00:00Z' }, signingKey));
});

test('snapshot authority signs exact completeness, terminal checkpoint and canonical event set', () => {
  const manifest = fixture();
  assert.deepEqual(verifyM4ReconciliationSnapshot(manifest, key('snapshot-authority-key', 1)), manifest);
  assert.equal(manifest.eventCount, 2); assert.match(manifest.eventSetDigest, /^sha256:[a-f0-9]{64}$/);
});

test('tamper, wrong authority, extras and malformed timestamps fail closed', () => {
  const manifest = fixture();
  for (const changed of [
    { ...manifest, eventCount: 1 },
    { ...manifest, eventFileDigest: digest('f') },
    { ...manifest, capturedAt: '2026-02-30T00:00:00Z' },
    { ...manifest, extra: true },
  ]) assert.throws(() => verifyM4ReconciliationSnapshot(changed, key('snapshot-authority-key', 1)));
  assert.throws(() => verifyM4ReconciliationSnapshot(manifest, key('snapshot-authority-key', 2)));
});

test('event accumulator rejects duplicate, reordered and post-finish additions', () => {
  const duplicate = createM4ReconciliationEventAccumulator(); duplicate.add(event(1));
  assert.throws(() => duplicate.add(event(1)), { code: 'm4_reconciliation_snapshot_event_order_invalid' });
  const reversed = createM4ReconciliationEventAccumulator(); reversed.add(event(2));
  assert.throws(() => reversed.add(event(1)), { code: 'm4_reconciliation_snapshot_event_order_invalid' });
  const closed = createM4ReconciliationEventAccumulator(); closed.add(event(1)); closed.finish();
  assert.throws(() => closed.add(event(2)), { code: 'm4_reconciliation_snapshot_event_order_invalid' });
});
