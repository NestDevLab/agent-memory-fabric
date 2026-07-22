import assert from 'node:assert/strict';
import test from 'node:test';

import {
  aggregatePauseCheckpointInputs,
  createPauseManifest,
} from '../src/migration-pause.mjs';
import { createM4RollbackManifest } from '../src/migration/m4-backfill-gate.mjs';
import {
  createM4ReconciliationManifest,
  verifyM4ReconciliationManifest,
} from '../src/migration/m4-reconciliation-manifest.mjs';
import { M4_DIMENSIONS, reconcileM4 } from '../src/migration/m4-reconciliation-reader.mjs';

const digest = character => `sha256:${character.repeat(64)}`;
const checkpoint = (id, character) => ({ id, digest: digest(character) });
const keyDocument = (keyId, byte) => ({
  schema: 'amf.migration-signing-key/v1',
  keyId,
  key: Buffer.alloc(32, byte).toString('base64'),
});
const pauseKey = keyDocument('pause-key-001', 1);
const rollbackKey = keyDocument('rollback-key-001', 2);
const reconciliationKey = keyDocument('reconciliation-key-001', 3);

function pauseFixture() {
  const child = {
    schema: 'amf.migration-pause-checkpoints/v1',
    manifestId: 'pause-manifest-001',
    revision: 1,
    keyId: pauseKey.keyId,
    pause: {
      state: 'paused',
      collectorCursor: checkpoint('collector-cursor-001', '1'),
      pendingOutbox: checkpoint('pending-outbox-001', '2'),
      acknowledgements: checkpoint('acknowledgements-001', '3'),
      deadLetters: checkpoint('dead-letters-001', '4'),
      sourceCheckpoint: checkpoint('source-checkpoint-001', '5'),
      nativeTranscriptAuthority: checkpoint('native-authority-001', '6'),
      evidence: { id: `pause-collector-${'a'.repeat(64)}`, digest: digest('7') },
    },
  };
  const roster = {
    schema: 'amf.migration-pause-collector-roster/v1',
    manifestId: child.manifestId,
    revision: child.revision,
    keyId: child.keyId,
    collectors: [child.pause.evidence.id],
  };
  return createPauseManifest(aggregatePauseCheckpointInputs([child], roster), pauseKey);
}

function evidenceFor(manifest) {
  return {
    manifestId: manifest.manifestId,
    digest: manifest.integrity.payloadDigest,
    signature: manifest.integrity.signature,
  };
}

function rollbackFixture(pauseManifest, overrides = {}) {
  return createM4RollbackManifest({
    schema: 'amf.migration-manifest/v1',
    manifestId: 'rollback-manifest-001',
    phase: 'rollback',
    revision: 1,
    rollback: {
      pauseEvidence: overrides.pauseEvidence ?? evidenceFor(pauseManifest),
      sourceCheckpoint: overrides.sourceCheckpoint ?? pauseManifest.pause.sourceCheckpoint,
      targetCheckpoint: checkpoint('target-checkpoint-001', '8'),
      compatibilityRouteRevision: 'compatibility-route-001',
      recoveryCopy: checkpoint('recovery-copy-001', '9'),
      restoreTest: overrides.restoreTest ?? 'passed',
    },
  }, rollbackKey);
}

function staticEvidence() {
  return {
    pausedInterval: {
      start: checkpoint('pause-start-001', '1'),
      end: checkpoint('pause-end-001', '2'),
    },
    replayQueues: {
      pendingOutbox: checkpoint('queue-pending-001', '3'),
      acknowledgements: checkpoint('queue-ack-001', '4'),
      deadLetters: checkpoint('queue-dead-001', '5'),
    },
    sourceCheckpoints: {
      collectorCursor: checkpoint('source-cursor-001', '6'),
      sourceCheckpoint: checkpoint('source-checkpoint-002', '7'),
      nativeTranscriptAuthority: checkpoint('native-authority-002', '8'),
    },
  };
}

function event(index, overrides = {}) {
  return {
    eventId: `cevt_${index.toString().padStart(8, '0')}`,
    payloadDigest: overrides.payloadDigest ?? digest(String(index)),
    logicalDigest: overrides.logicalDigest ?? digest(String(index + 1)),
    sourceOccurredAt: '2026-01-01T00:00:00Z',
    occurredAt: '2026-01-01T00:00:00Z',
    state: 'active',
  };
}

function iterable(values) {
  return { async *[Symbol.asyncIterator]() { yield* values; } };
}

async function report(source, target, evidence = staticEvidence()) {
  return reconcileM4({
    source: iterable(source),
    target: iterable(target),
    sourceEvidence: evidence,
    targetEvidence: structuredClone(evidence),
  });
}

function input(reportValue, overrides = {}) {
  const pauseManifest = overrides.pauseManifest ?? pauseFixture();
  return {
    manifestId: 'reconciliation-manifest-001',
    revision: 1,
    report: reportValue,
    pauseManifest,
    pauseKeyDocument: overrides.pauseKeyDocument ?? pauseKey,
    rollbackManifest: overrides.rollbackManifest ?? rollbackFixture(pauseManifest),
    rollbackKeyDocument: overrides.rollbackKeyDocument ?? rollbackKey,
    reconciliationKeyDocument: overrides.reconciliationKeyDocument ?? reconciliationKey,
  };
}

async function rejects(call, code) {
  await assert.rejects(call, error => error?.code === code && error.message === code);
}

test('creates and independently verifies a complete standard reconciliation manifest', async () => {
  const reportValue = await report([event(1)], [event(1)]);
  const manifest = createM4ReconciliationManifest(input(reportValue));
  const verified = verifyM4ReconciliationManifest(manifest, reconciliationKey);
  assert.deepEqual(verified, manifest);
  assert.deepEqual(Object.keys(manifest).sort(), [
    'integrity', 'manifestId', 'phase', 'reconciliation', 'revision', 'schema',
  ]);
  assert.equal(manifest.schema, 'amf.migration-manifest/v1');
  assert.equal(manifest.phase, 'reconciliation');
  assert.equal(manifest.reconciliation.state, 'complete');
  assert.deepEqual(manifest.reconciliation.dimensions, M4_DIMENSIONS);
  assert.equal(manifest.reconciliation.unresolvedMismatchCount, 0);
  assert.doesNotMatch(JSON.stringify(manifest), /dimensionEvidence|mismatchSamples|synthetic visible|private/);
});

test('signs a truthful pending report without presenting it as complete', async () => {
  const reportValue = await report([event(1)], [event(2)]);
  const manifest = createM4ReconciliationManifest(input(reportValue));
  assert.equal(manifest.reconciliation.state, 'pending');
  assert.equal(manifest.reconciliation.completeness, 1);
  assert.ok(manifest.reconciliation.unresolvedMismatchCount > 0);
  assert.deepEqual(verifyM4ReconciliationManifest(manifest, reconciliationKey), manifest);
});

test('rejects tampered report binding, evidence shapes, samples, and mismatch arithmetic', async () => {
  const reportValue = await report([event(1)], [event(2)]);
  const mutations = [];
  const binding = structuredClone(reportValue);
  binding.dimensionsBinding.digest = digest('f');
  mutations.push(binding);
  const evidence = structuredClone(reportValue);
  evidence.dimensionEvidence[0].source.privateContent = 'forbidden';
  mutations.push(evidence);
  const sample = structuredClone(reportValue);
  sample.mismatchSamples[0].kind = 'private-kind';
  mutations.push(sample);
  const arithmetic = structuredClone(reportValue);
  arithmetic.unresolvedMismatchCount += 1;
  mutations.push(arithmetic);
  for (const mutation of mutations) {
    await rejects(
      async () => createM4ReconciliationManifest(input(mutation)),
      'm4_reconciliation_manifest_report_invalid',
    );
  }
});

test('requires verified aggregate pause and exact rollback linkage with a passed restore test', async () => {
  const reportValue = await report([event(1)], [event(1)]);
  const pauseManifest = pauseFixture();
  const tamperedPause = structuredClone(pauseManifest);
  tamperedPause.integrity.signature = 'a'.repeat(43);
  await rejects(
    async () => createM4ReconciliationManifest(input(reportValue, { pauseManifest: tamperedPause })),
    'm4_reconciliation_manifest_evidence_invalid',
  );

  const wrongLink = rollbackFixture(pauseManifest, {
    pauseEvidence: { ...evidenceFor(pauseManifest), digest: digest('f') },
  });
  await rejects(
    async () => createM4ReconciliationManifest(input(reportValue, { pauseManifest, rollbackManifest: wrongLink })),
    'm4_reconciliation_manifest_evidence_invalid',
  );

  const wrongSource = rollbackFixture(pauseManifest, {
    sourceCheckpoint: checkpoint('other-source-001', 'e'),
  });
  await rejects(
    async () => createM4ReconciliationManifest(input(reportValue, { pauseManifest, rollbackManifest: wrongSource })),
    'm4_reconciliation_manifest_evidence_invalid',
  );

  const untested = rollbackFixture(pauseManifest, { restoreTest: 'not-run' });
  await rejects(
    async () => createM4ReconciliationManifest(input(reportValue, { pauseManifest, rollbackManifest: untested })),
    'm4_reconciliation_manifest_evidence_invalid',
  );
});

test('verifier rejects wrong keys, payload tamper, signature tamper, and extra fields', async () => {
  const manifest = createM4ReconciliationManifest(input(await report([event(1)], [event(1)])));
  await rejects(
    async () => verifyM4ReconciliationManifest(manifest, keyDocument('other-key-001', 3)),
    'm4_reconciliation_manifest_key_id_mismatch',
  );
  const payload = structuredClone(manifest);
  payload.revision = 2;
  await rejects(
    async () => verifyM4ReconciliationManifest(payload, reconciliationKey),
    'm4_reconciliation_manifest_digest_mismatch',
  );
  const signature = structuredClone(manifest);
  signature.integrity.signature = 'a'.repeat(43);
  await rejects(
    async () => verifyM4ReconciliationManifest(signature, reconciliationKey),
    'm4_reconciliation_manifest_signature_mismatch',
  );
  const extra = structuredClone(manifest);
  extra.privateContent = 'forbidden';
  await rejects(
    async () => verifyM4ReconciliationManifest(extra, reconciliationKey),
    'm4_reconciliation_manifest_invalid',
  );
});

test('snapshots getters once, isolates inputs and outputs, and keeps hostile errors content-free', async () => {
  const reportValue = await report([event(1)], [event(1)]);
  const value = input(reportValue);
  let reportReads = 0;
  let storedReport = value.report;
  Object.defineProperty(value, 'report', {
    enumerable: true,
    get() { reportReads += 1; return storedReport; },
    set(next) { storedReport = next; },
  });
  const manifest = createM4ReconciliationManifest(value);
  assert.equal(reportReads, 1);
  reportValue.dimensions = ['changed', ...reportValue.dimensions.slice(1)];
  value.pauseManifest.pause.state = 'changed';
  assert.deepEqual(manifest.reconciliation.dimensions, M4_DIMENSIONS);
  const verified = verifyM4ReconciliationManifest(manifest, reconciliationKey);
  verified.reconciliation.dimensions[0] = 'changed';
  assert.deepEqual(verifyM4ReconciliationManifest(manifest, reconciliationKey), manifest);

  const hostile = input(await report([event(1)], [event(1)]));
  Object.defineProperty(hostile, 'report', {
    enumerable: true,
    get() { throw new Error('private report detail'); },
  });
  await rejects(
    async () => createM4ReconciliationManifest(hostile),
    'm4_reconciliation_manifest_input_invalid',
  );
});
