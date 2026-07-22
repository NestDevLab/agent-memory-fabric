import assert from 'node:assert/strict';
import test from 'node:test';

import { aggregatePauseCheckpointInputs, createPauseManifest } from '../src/migration-pause.mjs';
import { createM4RollbackManifest } from '../src/migration/m4-backfill-gate.mjs';
import { createM4RecoveryPairManifest, verifyM4RecoveryPairManifest } from '../src/migration/m4-recovery-pair.mjs';
import { createM4ReconciliationManifest } from '../src/migration/m4-reconciliation-manifest.mjs';
import { reconcileM4 } from '../src/migration/m4-reconciliation-reader.mjs';

const digest = char => `sha256:${char.repeat(64)}`;
const cp = (id, char) => ({ id, digest: digest(char) });
const key = (id, byte) => ({ schema: 'amf.migration-signing-key/v1', keyId: id, key: Buffer.alloc(32, byte).toString('base64') });
const pauseKey = key('pause-key-001', 1), rollbackKey = key('rollback-key-001', 2), reconciliationKey = key('reconciliation-key-001', 3), recoveryKey = key('recovery-key-001', 4);
const evidenceFor = manifest => ({ manifestId: manifest.manifestId, digest: manifest.integrity.payloadDigest, signature: manifest.integrity.signature });
const iterable = values => ({ async *[Symbol.asyncIterator]() { yield* values; } });
function pause() {
  const child = { schema: 'amf.migration-pause-checkpoints/v1', manifestId: 'pause-manifest-001', revision: 1, keyId: pauseKey.keyId, pause: { state: 'paused', collectorCursor: cp('collector-cursor-001', '1'), pendingOutbox: cp('pending-outbox-001', '2'), acknowledgements: cp('acknowledgements-001', '3'), deadLetters: cp('dead-letters-001', '4'), sourceCheckpoint: cp('source-checkpoint-001', '5'), nativeTranscriptAuthority: cp('native-authority-001', '6'), evidence: { id: `pause-collector-${'a'.repeat(64)}`, digest: digest('7') } } };
  return createPauseManifest(aggregatePauseCheckpointInputs([child], { schema: 'amf.migration-pause-collector-roster/v1', manifestId: child.manifestId, revision: 1, keyId: pauseKey.keyId, collectors: [child.pause.evidence.id] }), pauseKey);
}
async function reconciliation(equal = true) {
  const sourceEvidence = { pausedInterval: { start: cp('pause-start-001', '1'), end: cp('pause-end-001', '2') }, replayQueues: { pendingOutbox: cp('pending-queue-001', '3'), acknowledgements: cp('ack-queue-001', '4'), deadLetters: cp('dead-queue-001', '5') }, sourceCheckpoints: { collectorCursor: cp('cursor-001', '6'), sourceCheckpoint: cp('source-002', '7'), nativeTranscriptAuthority: cp('authority-002', '8') } };
  const event = number => ({ eventId: `cevt_${String(number).padStart(8, '0')}`, payloadDigest: digest('a'), logicalDigest: digest('b'), sourceOccurredAt: '2026-01-01T00:00:00Z', occurredAt: '2026-01-01T00:00:00Z', state: 'active' });
  const report = await reconcileM4({ source: iterable([event(1)]), target: iterable([event(equal ? 1 : 2)]), sourceEvidence, targetEvidence: structuredClone(sourceEvidence) });
  const paused = pause();
  const rollback = createM4RollbackManifest({ schema: 'amf.migration-manifest/v1', manifestId: 'rollback-manifest-001', phase: 'rollback', revision: 1, rollback: { pauseEvidence: evidenceFor(paused), sourceCheckpoint: paused.pause.sourceCheckpoint, targetCheckpoint: cp('target-checkpoint-001', '9'), compatibilityRouteRevision: 'compatibility-route-001', recoveryCopy: cp('rollback-copy-001', 'a'), restoreTest: 'passed' } }, rollbackKey);
  return createM4ReconciliationManifest({ manifestId: 'reconciliation-manifest-001', revision: 1, report, pauseManifest: paused, pauseKeyDocument: pauseKey, rollbackManifest: rollback, rollbackKeyDocument: rollbackKey, reconciliationKeyDocument: reconciliationKey });
}
function record(archive, suffix) { const chars = archive === 'legacy-v2' ? ['1', '2', '3', '4', '5'] : ['6', '7', '8', '9', 'a']; return { archive, recoveryCopy: cp(`recovery-copy-${suffix}`, chars[0]), catalogSnapshot: cp(`catalog-snapshot-${suffix}`, chars[1]), isolatedRestoreTarget: cp(`restore-target-${suffix}`, chars[2]), restoredCheckpoint: cp(`restored-checkpoint-${suffix}`, chars[3]), verification: cp(`verification-${suffix}`, chars[4]), restoreTest: 'passed' }; }
async function input(overrides = {}) { return { manifestId: 'recovery-pair-001', revision: 1, reconciliationManifest: overrides.reconciliationManifest ?? await reconciliation(), reconciliationKeyDocument: reconciliationKey, legacyRecord: overrides.legacyRecord ?? record('legacy-v2', 'legacy'), v3Record: overrides.v3Record ?? record('v3', 'v3'), recoveryKeyDocument: recoveryKey }; }
async function rejects(call, code) { await assert.rejects(call, error => error?.code === code); }

test('creates and verifies a complete independent recovery pair', async () => {
  const request = await input(); const manifest = createM4RecoveryPairManifest(request); request.legacyRecord.archive = 'mutated';
  assert.deepEqual(verifyM4RecoveryPairManifest(manifest, recoveryKey), manifest);
  assert.equal(manifest.schema, 'amf.m4-recovery-pair/v1');
  assert.equal(Object.hasOwn(manifest, 'phase'), false);
  assert.deepEqual(manifest.archives.map(item => item.archive), ['legacy-v2', 'v3']);
  assert.doesNotMatch(JSON.stringify(manifest), /content|private|path|directory/i);
});
test('rejects pending reconciliation and reused copies/tests', async () => {
  await rejects(async () => createM4RecoveryPairManifest(await input({ reconciliationManifest: await reconciliation(false) })), 'm4_recovery_pair_reconciliation_incomplete');
  const shared = record('v3', 'legacy');
  await rejects(async () => createM4RecoveryPairManifest(await input({ v3Record: shared })), 'm4_recovery_pair_record_invalid');
  const crossField = record('v3', 'v3');
  crossField.verification = cp('recovery-copy-legacy', '1');
  await rejects(async () => createM4RecoveryPairManifest(await input({ v3Record: crossField })), 'm4_recovery_pair_record_invalid');
});
test('rejects record extras, field tamper, wrong keys, signatures, and output mutation', async () => {
  const extra = record('legacy-v2', 'legacy'); extra.content = 'forbidden';
  await rejects(async () => createM4RecoveryPairManifest(await input({ legacyRecord: extra })), 'm4_recovery_pair_record_invalid');
  const manifest = createM4RecoveryPairManifest(await input()); const changed = structuredClone(manifest); changed.archives[0].verification.digest = digest('f');
  await rejects(async () => verifyM4RecoveryPairManifest(changed, recoveryKey), 'm4_recovery_pair_digest_mismatch');
  await rejects(async () => verifyM4RecoveryPairManifest(manifest, key('other-key-001', 4)), 'm4_recovery_pair_key_id_mismatch');
  const signature = structuredClone(manifest); signature.integrity.signature = 'a'.repeat(43);
  await rejects(async () => verifyM4RecoveryPairManifest(signature, recoveryKey), 'm4_recovery_pair_signature_mismatch');
  const verified = verifyM4RecoveryPairManifest(manifest, recoveryKey); verified.archives[0].archive = 'changed'; assert.equal(manifest.archives[0].archive, 'legacy-v2');
});
test('rejects hostile getters without reading content', async () => {
  const hostile = {}; Object.defineProperty(hostile, 'manifestId', { enumerable: true, get() { throw new Error('getter'); } });
  await rejects(async () => createM4RecoveryPairManifest(hostile), 'm4_recovery_pair_input_invalid');
});
test('does not widen the standard migration manifest phase vocabulary', async () => {
  const manifest = createM4RecoveryPairManifest(await input());
  const mislabeled = { ...manifest, schema: 'amf.migration-manifest/v1', phase: 'recovery' };
  await rejects(async () => verifyM4RecoveryPairManifest(mislabeled, recoveryKey), 'm4_recovery_pair_manifest_invalid');
});
