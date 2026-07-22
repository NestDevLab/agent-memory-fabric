import { aggregatePauseCheckpointInputs, createPauseManifest } from '../../src/migration-pause.mjs';
import { createM4RollbackManifest } from '../../src/migration/m4-backfill-gate.mjs';
import { createM4ConversationExtractorAliases } from '../../src/migration/m4-conversation-extractor-aliases.mjs';
import { collectM4CatalogReferenceSnapshot, collectM4SelectorScopeSnapshot } from '../../src/migration/m4-authority-snapshots.mjs';
import { createM4CutoverCanaryManifest } from '../../src/migration/m4-cutover-canary.mjs';
import { createM4PreservationProof } from '../../src/migration/m4-preservation-proof.mjs';
import { createM4ReconciliationManifest } from '../../src/migration/m4-reconciliation-manifest.mjs';
import { reconcileM4 } from '../../src/migration/m4-reconciliation-reader.mjs';
import { createM4RecoveryPairManifest } from '../../src/migration/m4-recovery-pair.mjs';

export const digest = character => `sha256:${character.repeat(64)}`;
export const checkpoint = (id, character) => ({ id, digest: digest(character) });
export const keyDocument = (keyId, byte) => ({ schema: 'amf.migration-signing-key/v1', keyId, key: Buffer.alloc(32, byte).toString('base64') });
export const evidenceFor = (manifest, state = null) => ({ manifestId: manifest.manifestId, digest: manifest.integrity.payloadDigest,
  signature: manifest.integrity.signature, ...(state === null ? {} : { state }) });

const iterable = values => ({ async *[Symbol.asyncIterator]() { yield* values; } });
function pause(pauseKey) {
  const child = { schema: 'amf.migration-pause-checkpoints/v1', manifestId: 'pause-cutover-one', revision: 1, keyId: pauseKey.keyId,
    pause: { state: 'paused', collectorCursor: checkpoint('cutover-cursor', '1'), pendingOutbox: checkpoint('cutover-pending', '2'),
      acknowledgements: checkpoint('cutover-acknowledgements', '3'), deadLetters: checkpoint('cutover-dead-letters', '4'),
      sourceCheckpoint: checkpoint('cutover-source-checkpoint', '5'), nativeTranscriptAuthority: checkpoint('cutover-native-authority', '6'),
      evidence: { id: `pause-collector-${'a'.repeat(64)}`, digest: digest('7') } } };
  const roster = { schema: 'amf.migration-pause-collector-roster/v1', manifestId: child.manifestId, revision: 1,
    keyId: pauseKey.keyId, collectors: [child.pause.evidence.id] };
  return createPauseManifest(aggregatePauseCheckpointInputs([child], roster), pauseKey);
}
function recoveryRecord(archive) {
  const suffix = archive === 'legacy-v2' ? 'legacy' : 'vthree'; const chars = archive === 'legacy-v2' ? ['1', '2', '3', '4', '5'] : ['6', '7', '8', '9', 'a'];
  return { archive, recoveryCopy: checkpoint(`${suffix}-recovery-copy`, chars[0]), catalogSnapshot: checkpoint(`${suffix}-catalog-snapshot`, chars[1]),
    isolatedRestoreTarget: checkpoint(`${suffix}-restore-target`, chars[2]), restoredCheckpoint: checkpoint(`${suffix}-restored-checkpoint`, chars[3]),
    verification: checkpoint(`${suffix}-recovery-verification`, chars[4]), restoreTest: 'passed' };
}

export async function m4CutoverFixture() {
  const keys = { pause: keyDocument('cutover-pause-key', 1), rollback: keyDocument('cutover-rollback-key', 2),
    reconciliation: keyDocument('cutover-reconciliation-key', 3), recovery: keyDocument('cutover-recovery-key', 4),
    alias: keyDocument('cutover-alias-key', 5), canary: keyDocument('cutover-canary-key', 6),
    preservation: keyDocument('cutover-preservation-key', 7), authorization: keyDocument('cutover-authorization-key', 8),
    cleanup: keyDocument('cutover-cleanup-key', 9), selectorScope: keyDocument('cutover-selector-scope-key', 10),
    catalogSnapshot: keyDocument('cutover-catalog-snapshot-key', 11) };
  const paused = pause(keys.pause);
  const rollback = createM4RollbackManifest({ schema: 'amf.migration-manifest/v1', manifestId: 'cutover-rollback-one', phase: 'rollback', revision: 1,
    rollback: { pauseEvidence: evidenceFor(paused), sourceCheckpoint: paused.pause.sourceCheckpoint, targetCheckpoint: checkpoint('cutover-target-checkpoint', '8'),
      compatibilityRouteRevision: 'cutover-route-revision', recoveryCopy: checkpoint('cutover-rollback-copy', '9'), restoreTest: 'passed' } }, keys.rollback);
  const sourceEvidence = { pausedInterval: { start: checkpoint('cutover-pause-start', '1'), end: checkpoint('cutover-pause-end', '2') },
    replayQueues: { pendingOutbox: checkpoint('cutover-queue-pending', '3'), acknowledgements: checkpoint('cutover-queue-ack', '4'), deadLetters: checkpoint('cutover-queue-dead', '5') },
    sourceCheckpoints: { collectorCursor: checkpoint('cutover-source-cursor', '6'), sourceCheckpoint: checkpoint('cutover-source-final', '7'), nativeTranscriptAuthority: checkpoint('cutover-authority-final', '8') } };
  const event = { eventId: 'cevt_cutoverfixture01', payloadDigest: digest('a'), logicalDigest: digest('b'), sourceOccurredAt: '2026-01-01T00:00:00Z', occurredAt: '2026-01-01T00:00:00Z', state: 'active' };
  const report = await reconcileM4({ source: iterable([event]), target: iterable([event]), sourceEvidence, targetEvidence: structuredClone(sourceEvidence) });
  const reconciliation = createM4ReconciliationManifest({ manifestId: 'cutover-reconciliation-one', revision: 1, report,
    pauseManifest: paused, pauseKeyDocument: keys.pause, rollbackManifest: rollback, rollbackKeyDocument: keys.rollback,
    reconciliationKeyDocument: keys.reconciliation });
  const recovery = createM4RecoveryPairManifest({ manifestId: 'cutover-recovery-one', revision: 1, reconciliationManifest: reconciliation,
    reconciliationKeyDocument: keys.reconciliation, legacyRecord: recoveryRecord('legacy-v2'), v3Record: recoveryRecord('v3'), recoveryKeyDocument: keys.recovery });
  const alias = createM4ConversationExtractorAliases({ coveredThrough: '2026-01-01T00:00:00Z', aliases: [] }, Buffer.from(keys.alias.key, 'base64'));
  const canary = createM4CutoverCanaryManifest({ manifestId: 'cutover-canary-one', revision: 1, keyDocument: keys.canary,
    policy: { start: '2026-01-02T00:00:00Z', end: '2026-01-02T01:00:00Z', maxSamples: 12,
      queue: { maxDepth: 1, maxOldestAgeMs: 1000 }, latency: { maxP95Ms: 100, maxP99Ms: 200, maxRequestMs: 500 }, allowed5xx: 0,
      zeroRequiredCategories: ['reader', 'config', 'auth', 'integrity', 'identity', 'cursorMigration', 'unexpectedDuplicate'] },
    observations: { start: '2026-01-02T00:00:00.000000001Z', end: '2026-01-02T00:59:59.999999999Z', sampleCount: 12,
      queue: { maxDepth: 1, maxOldestAgeMs: 1000 }, latency: { p95Ms: 100, p99Ms: 200, maxRequestMs: 500 },
      errors: { http5xx: 0, reader: 0, config: 0, auth: 0, integrity: 0, identity: 0, cursorMigration: 0, unexpectedDuplicate: 0 },
      rollbackDrill: { state: 'passed', configurationRevision: checkpoint('cutover-canary-config', 'c'), verification: checkpoint('cutover-canary-rollback', 'd') } } });
  const sourceId = 'src_cutoverfixture1';
  const policy = { schema: 'amf.content-protection-policy/v1', revision: 'cutover-policy-v2', defaults: { conversation: 'plaintext', proposal: 'plaintext', 'canonical-memory': 'plaintext', document: 'plaintext' },
    rules: [{ sourceInstanceId: sourceId, contentClass: 'conversation', enabled: true, codec: 'aes-256-gcm', writeKeyRef: 'key:cutover-v2', readKeyRefs: ['key:cutover-v2'], compression: 'deflate-raw', readPlaintext: false }] };
  const selectorScope = await collectM4SelectorScopeSnapshot({ snapshotId: 'cutover-selector-scope-one', revision: 1, policy,
    observedAt: '2026-01-01T23:59:00Z', validThrough: '2026-01-03T00:00:00Z',
    selectorSource: iterable([{ sourceInstanceId: sourceId, contentClass: 'conversation' }]), keyDocument: keys.selectorScope });
  const preservation = createM4PreservationProof({ manifestId: 'cutover-preservation-one', revision: 1, signingKeyDocument: keys.preservation,
    provedAt: '2026-01-02T01:01:00Z', policy, selectorScopeManifest: selectorScope,
    dispositions: [{ sourceInstanceId: sourceId, contentClass: 'conversation', scannedPlaintextCount: 3, retainedEncryptedCount: 1, cleanupTargetCount: 2, binding: checkpoint('cutover-disposition', 'e') }],
    preservedSharedData: [{ contentClass: 'proposal', count: 2, binding: checkpoint('cutover-proposals', 'f') },
      { contentClass: 'canonical-memory', count: 3, binding: checkpoint('cutover-memories', '0') },
      { contentClass: 'document', count: 4, binding: checkpoint('cutover-documents', 'b') }],
    rollbackPolicyBinding: { revision: 'cutover-policy-v1', digest: digest('c') }, restoreTest: { state: 'passed', evidence: checkpoint('cutover-policy-restore', 'd') } },
  { selectorScopeKeyDocument: keys.selectorScope });
  const catalogSnapshot = await collectM4CatalogReferenceSnapshot({ snapshotId: 'cutover-catalog-snapshot-one', revision: 1,
    catalogRevision: checkpoint('cutover-catalog-revision', '5'), observedAt: '2026-01-02T01:02:00Z', validThrough: '2026-01-03T00:00:00Z',
    catalogSource: iterable([
      { id: 'cutover-target-one', digest: digest('6'), objectType: 'transcript-row', sourceInstanceId: sourceId, contentClass: 'conversation', references: [] },
      { id: 'cutover-target-two', digest: digest('7'), objectType: 'transcript-blob', sourceInstanceId: sourceId, contentClass: 'conversation', references: [] },
      { id: 'cutover-retained-one', digest: digest('8'), objectType: 'transcript-row', sourceInstanceId: sourceId, contentClass: 'conversation', references: [checkpoint('cutover-v3-reference', '9')] },
    ]), keyDocument: keys.catalogSnapshot });
  return { keys, paused, rollback, reconciliation, recovery, alias, canary, policy, selectorScope, preservation, catalogSnapshot,
    authorizationInput: { manifestId: 'cutover-authorization-one', revision: 1, reconciliationManifest: reconciliation,
      reconciliationKeyDocument: keys.reconciliation, recoveryManifest: recovery, recoveryKeyDocument: keys.recovery,
      aliasManifest: alias, aliasKeyDocument: keys.alias, canaryManifest: canary, canaryKeyDocument: keys.canary,
      preservationManifest: preservation, preservationKeyDocument: keys.preservation,
      selectorScopeManifest: selectorScope, authorizedAt: '2026-01-02T01:03:00Z',
      routeConfiguration: { publicReader: { mode: 'active', revision: checkpoint('cutover-public-reader', '1') },
        extractorReader: { mode: 'v3', revision: checkpoint('cutover-extractor-reader', '2'), stateGeneration: 'conversation-v3',
          stateBoundary: checkpoint('cutover-extractor-boundary', '3'), coverageVerification: checkpoint('cutover-coverage-verification', '4') } },
      rollbackRevision: checkpoint('cutover-canary-config', 'c'), authorizationKeyDocument: keys.authorization } };
}
