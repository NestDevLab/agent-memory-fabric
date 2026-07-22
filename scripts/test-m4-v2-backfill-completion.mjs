import assert from 'node:assert/strict';
import test from 'node:test';

import { createM4V2ArchiveBackfillCompletion, deriveM4V2ArchiveRegistryBinding, verifyM4V2ArchiveBackfillCompletion } from '../src/migration/m4-v2-backfill-completion.mjs';
import { attestM4V2CatalogRevision } from '../src/migration/m4-v2-catalog-revision-attestation.mjs';
import { createM4RollbackManifest } from '../src/migration/m4-backfill-gate.mjs';
import { aggregatePauseCheckpointInputs, createPauseManifest } from '../src/migration-pause.mjs';
import { planM4V2Backfill } from '../src/migration/m4-v2-backfill-runner.mjs';

const digest = value => `sha256:${value.repeat(64)}`;
const key = (keyId, byte) => ({ schema: 'amf.migration-signing-key/v1', keyId, key: Buffer.alloc(32, byte).toString('base64') });
function countedGetters(value) {
  const reads = Object.fromEntries(Object.keys(value).map(name => [name, 0])); const hostile = {};
  for (const [name, entry] of Object.entries(value)) Object.defineProperty(hostile, name, { enumerable: true, get() { reads[name] += 1; return entry; } });
  return { hostile, reads };
}
function gateInput() { const pauseKey = key('completion-pause-key', 1); const rollbackKey = key('completion-rollback-key', 2); const source = { id: 'source-checkpoint-completion', digest: digest('1') }; const input = { schema: 'amf.migration-pause-checkpoints/v1', manifestId: 'pause-manifest-completion', revision: 1, keyId: pauseKey.keyId, pause: { state: 'paused', collectorCursor: { id: 'collector-cursor-completion', digest: digest('2') }, pendingOutbox: { id: 'pending-outbox-completion', digest: digest('3') }, acknowledgements: { id: 'acknowledgements-completion', digest: digest('4') }, deadLetters: { id: 'dead-letters-completion', digest: digest('5') }, sourceCheckpoint: source, nativeTranscriptAuthority: { id: 'native-authority-completion', digest: digest('6') }, evidence: { id: `pause-collector-${'a'.repeat(64)}`, digest: digest('7') } } }; const roster = { schema: 'amf.migration-pause-collector-roster/v1', manifestId: input.manifestId, revision: 1, keyId: pauseKey.keyId, collectors: [input.pause.evidence.id] }; const pause = createPauseManifest(aggregatePauseCheckpointInputs([input], roster), pauseKey); const rollback = createM4RollbackManifest({ schema: 'amf.migration-manifest/v1', manifestId: 'rollback-manifest-completion', phase: 'rollback', revision: 1, rollback: { pauseEvidence: { manifestId: pause.manifestId, digest: pause.integrity.payloadDigest, signature: pause.integrity.signature }, sourceCheckpoint: pause.pause.sourceCheckpoint, targetCheckpoint: { id: 'target-checkpoint-completion', digest: digest('8') }, compatibilityRouteRevision: 'compatibility-route-completion', recoveryCopy: { id: 'recovery-copy-completion', digest: digest('9') }, restoreTest: 'passed' } }, rollbackKey); return { runId: 'm4-completion-001', phase: 'v2-archive', pauseManifest: pause, pauseKeyDocument: pauseKey, rollbackManifest: rollback, rollbackKeyDocument: rollbackKey }; }

test('signs a complete V2 archive completion with independent catalog and completion keys', async () => {
  const gate = gateInput(); const runnerPlan = await planM4V2Backfill({ gateInput: gate, maxEvents: 1 }); const catalogKey = key('catalog-attestation-k1', 3); const completionKey = key('archive-completion-k1', 4); const catalog = { async listM4V2LogicalGroups() { return { items: [], next: null }; } }; const attestation = await attestM4V2CatalogRevision({ catalog, keyDocument: catalogKey, pageLimit: 50 }); const result = { schema: 'amf.m4-backfill-result/v1', runId: runnerPlan.runId, phase: 'v2-archive', processed: 0, duplicates: 0, lastCheckpoint: runnerPlan.sourceCheckpoint, complete: true }; const completion = await createM4V2ArchiveBackfillCompletion({ manifestId: 'v2-completion-test', revision: 1, gateInput: gate, runnerPlan, result, preCatalogAttestation: attestation, postCatalogAttestation: attestation, catalogAttestationKeyDocument: catalogKey, completionKeyDocument: completionKey });
  assert.deepEqual(verifyM4V2ArchiveBackfillCompletion(completion, completionKey), completion);
  const binding = deriveM4V2ArchiveRegistryBinding(completion, completionKey, attestation, catalogKey);
  assert.match(binding.completionDigest, /^sha256:/); assert.equal(binding.catalogRevisionDigest, attestation.traversal.catalogRevisionDigest);
  const tampered = structuredClone(completion); tampered.catalogAttestationDigest = digest('f'); assert.throws(() => verifyM4V2ArchiveBackfillCompletion(tampered, completionKey), { code: 'm4_v2_archive_completion_digest_mismatch' });
  const catalogDigestTamper = structuredClone(attestation); catalogDigestTamper.traversal.catalogRevisionDigest = digest('f');
  assert.throws(() => deriveM4V2ArchiveRegistryBinding(completion, completionKey, catalogDigestTamper, catalogKey), { code: 'm4_v2_catalog_attestation_invalid' });
  const substitutedCatalogKey = key('catalog-attestation-k2', 5);
  const substitutedAttestation = await attestM4V2CatalogRevision({ catalog, keyDocument: substitutedCatalogKey, pageLimit: 50 });
  assert.throws(() => deriveM4V2ArchiveRegistryBinding(completion, completionKey, substitutedAttestation, substitutedCatalogKey), { code: 'm4_v2_archive_completion_catalog_binding_mismatch' });
  const sameMaterialCatalogKey = { ...catalogKey, key: completionKey.key };
  const sameMaterialAttestation = await attestM4V2CatalogRevision({ catalog, keyDocument: sameMaterialCatalogKey, pageLimit: 50 });
  assert.throws(() => deriveM4V2ArchiveRegistryBinding(completion, completionKey, sameMaterialAttestation, sameMaterialCatalogKey), { code: 'm4_v2_archive_completion_key_separation_invalid' });
  await assert.rejects(() => createM4V2ArchiveBackfillCompletion({ manifestId: 'v2-completion-test', revision: 1, gateInput: gate, runnerPlan, result, preCatalogAttestation: attestation, postCatalogAttestation: attestation, catalogAttestationKeyDocument: catalogKey, completionKeyDocument: { ...catalogKey, keyId: 'other-key' } }), { code: 'm4_v2_archive_completion_key_separation_invalid' });
  const hostileCompletionKey = countedGetters(completionKey);
  assert.deepEqual(verifyM4V2ArchiveBackfillCompletion(completion, hostileCompletionKey.hostile), completion);
  assert.deepEqual(hostileCompletionKey.reads, { schema: 1, keyId: 1, key: 1 });
  const hostileCompletion = countedGetters(completion);
  assert.deepEqual(verifyM4V2ArchiveBackfillCompletion(hostileCompletion.hostile, completionKey), completion);
  assert.equal(Object.values(hostileCompletion.reads).every(reads => reads === 1), true);
  const malformedCompletionKey = { ...completionKey, key: 'not-base64' };
  await assert.rejects(() => createM4V2ArchiveBackfillCompletion({ manifestId: 'v2-completion-test', revision: 1, gateInput: gate, runnerPlan, result, preCatalogAttestation: attestation, postCatalogAttestation: attestation, catalogAttestationKeyDocument: catalogKey, completionKeyDocument: malformedCompletionKey }), { code: 'm4_v2_archive_completion_key_invalid' });
  assert.throws(() => deriveM4V2ArchiveRegistryBinding(completion, malformedCompletionKey, attestation, catalogKey), { code: 'm4_v2_archive_completion_key_invalid' });
});
