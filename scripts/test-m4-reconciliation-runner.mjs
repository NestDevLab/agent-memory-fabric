import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import { canonicalJson } from '../src/ingest/transcripts/canonical.mjs';
import { aggregatePauseCheckpointInputs, createPauseManifest } from '../src/migration-pause.mjs';
import { createM4RollbackManifest } from '../src/migration/m4-backfill-gate.mjs';
import { verifyM4ReconciliationManifest } from '../src/migration/m4-reconciliation-manifest.mjs';
import { planM4Reconciliation, runM4Reconciliation } from '../src/migration/m4-reconciliation-runner.mjs';

const key = (keyId, byte, bytes = 32) => ({ schema: 'amf.migration-signing-key/v1', keyId,
  key: Buffer.alloc(bytes, byte).toString('base64') });
const PAUSE_KEY = key('pause-key-runner', 1);
const ROLLBACK_KEY = key('rollback-key-runner', 2);
const LEGACY_KEY = key('legacy-key-runner', 3);
const NATIVE_KEY = key('native-key-runner', 4);
const RECONCILIATION_KEY = key('reconciliation-key-runner', 5);
const sha = value => `sha256:${crypto.createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`;
const checkpoint = (id, marker = id) => ({ id, digest: sha(marker) });
const sign = (document, domain, valueDigest) => crypto.createHmac('sha256', Buffer.from(document.key, 'base64'))
  .update(canonicalJson([domain, valueDigest, document.keyId]), 'utf8').digest('base64url');

function gateFixture() {
  const collector = `pause-collector-${'1'.repeat(64)}`;
  const child = { schema: 'amf.migration-pause-checkpoints/v1', manifestId: 'pause-manifest-runner',
    revision: 1, keyId: PAUSE_KEY.keyId, pause: { state: 'paused',
      collectorCursor: checkpoint('collector-cursor-runner'),
      pendingOutbox: checkpoint('pending-outbox-runner'),
      acknowledgements: checkpoint('acknowledgements-runner'),
      deadLetters: checkpoint('dead-letters-runner'),
      sourceCheckpoint: checkpoint('source-checkpoint-runner'),
      nativeTranscriptAuthority: checkpoint('native-authority-runner'),
      evidence: checkpoint(collector) } };
  const roster = { schema: 'amf.migration-pause-collector-roster/v1', manifestId: child.manifestId,
    revision: child.revision, keyId: child.keyId, collectors: [collector] };
  const pauseManifest = createPauseManifest(aggregatePauseCheckpointInputs([child], roster), PAUSE_KEY);
  const pauseEvidence = { manifestId: pauseManifest.manifestId,
    digest: pauseManifest.integrity.payloadDigest, signature: pauseManifest.integrity.signature };
  const rollbackManifest = createM4RollbackManifest({ schema: 'amf.migration-manifest/v1',
    manifestId: 'rollback-manifest-runner', phase: 'rollback', revision: 1,
    rollback: { pauseEvidence, sourceCheckpoint: pauseManifest.pause.sourceCheckpoint,
      targetCheckpoint: checkpoint('target-checkpoint-runner'),
      compatibilityRouteRevision: 'compatibility-route-runner',
      recoveryCopy: checkpoint('recovery-copy-runner'), restoreTest: 'passed' } }, ROLLBACK_KEY);
  return { runId: 'reconciliation-gate-runner', phase: 'paused-native', pauseManifest,
    pauseKeyDocument: PAUSE_KEY, rollbackManifest, rollbackKeyDocument: ROLLBACK_KEY };
}

function legacyCompletion(marker = 'legacy-authority') {
  const payload = { schema: 'amf.m4-legacy-group-replay-completion/v1', state: 'complete',
    authorityDigest: sha(marker), checkpoint: checkpoint('legacy-checkpoint-runner', marker) };
  const evidenceDigest = sha({ schema: 'amf.m4-legacy-group-replay-completion-evidence/v1',
    manifestId: 'legacy-manifest-runner', keyId: LEGACY_KEY.keyId, completion: payload });
  return { ...payload, evidence: { manifestId: 'legacy-manifest-runner', digest: evidenceDigest,
    signature: sign(LEGACY_KEY, 'amf.m4-legacy-group-replay-completion/v1/integrity', evidenceDigest) } };
}

function gateDigest(gateInput) {
  const pause = gateInput.pauseManifest;
  const rollback = gateInput.rollbackManifest;
  return sha({ schema: 'amf.m4-native-paused-phase-gate-evidence/v1',
    pauseEvidence: { manifestId: pause.manifestId, digest: pause.integrity.payloadDigest,
      signature: pause.integrity.signature },
    rollbackEvidence: { manifestId: rollback.manifestId, digest: rollback.integrity.payloadDigest,
      signature: rollback.integrity.signature }, sourceCheckpoint: rollback.rollback.sourceCheckpoint,
    targetCheckpoint: rollback.rollback.targetCheckpoint });
}

function nativeCompletion(gateInput, legacy, receiptMarker = 'receipts') {
  const payload = { schema: 'amf.m4-native-paused-phase-completion/v1', state: 'complete',
    runId: 'native-phase-runner', gateEvidenceDigest: gateDigest(gateInput),
    catalogDigest: sha('catalog'), legacyCompletionDigest: sha(legacy),
    receiptKeyId: 'receipt-key-runner', receiptDigest: sha(receiptMarker) };
  const checkpointDigest = sha({ schema: 'amf.m4-native-paused-phase-final-checkpoint/v1',
    runId: payload.runId, gateEvidenceDigest: payload.gateEvidenceDigest,
    catalogDigest: payload.catalogDigest, legacyCompletionDigest: payload.legacyCompletionDigest,
    receiptKeyId: payload.receiptKeyId, receiptDigest: payload.receiptDigest });
  payload.checkpoint = { id: `m4nativephase-${checkpointDigest.slice(7)}`, digest: checkpointDigest };
  const evidenceDigest = sha({ schema: 'amf.m4-native-paused-phase-completion-evidence/v1',
    manifestId: 'native-manifest-runner', keyId: NATIVE_KEY.keyId, completion: payload });
  return { ...payload, evidence: { manifestId: 'native-manifest-runner', keyId: NATIVE_KEY.keyId,
    digest: evidenceDigest,
    signature: sign(NATIVE_KEY, 'amf.m4-native-paused-phase-completion/v1/integrity', evidenceDigest) } };
}

function staticEvidence() { return { pausedInterval: { start: checkpoint('pause-start-runner'),
  end: checkpoint('pause-end-runner') }, replayQueues: {
  pendingOutbox: checkpoint('queue-pending-runner'), acknowledgements: checkpoint('queue-ack-runner'),
  deadLetters: checkpoint('queue-dead-runner') }, sourceCheckpoints: {
  collectorCursor: checkpoint('source-cursor-runner'), sourceCheckpoint: checkpoint('source-end-runner'),
  nativeTranscriptAuthority: checkpoint('source-native-runner') } }; }
const event = (number, overrides = {}) => ({ eventId: `cevt_event${String(number).padStart(4, '0')}`,
  payloadDigest: sha(`payload-${number}`), logicalDigest: sha(`logical-${number}`),
  sourceOccurredAt: `2026-01-01T00:00:0${number}Z`, occurredAt: `2026-01-01T00:01:0${number}Z`,
  state: 'active', ...overrides });
const events = rows => ({ async *[Symbol.asyncIterator]() { yield* rows; } });

function fixture() {
  const gateInput = gateFixture(); const legacy = legacyCompletion(); const native = nativeCompletion(gateInput, legacy);
  const evidence = staticEvidence();
  return { serial: { gateInput, legacyCompletion: legacy, legacyCompletionKeyDocument: LEGACY_KEY,
    nativePhaseCompletion: native, nativePhaseCompletionKeyDocument: NATIVE_KEY,
    sourceEvidence: evidence, targetEvidence: structuredClone(evidence), maxVisitedEvents: 100,
    maxMismatchSamples: 10, manifestId: 'reconciliation-manifest-runner', revision: 1,
    reconciliationKeyId: RECONCILIATION_KEY.keyId }, legacy, native, evidence };
}

function factories(value, sourceRows, targetRows, overrides = {}) {
  const closed = [];
  return { closed, value: { source: async () => ({ value: { events: events(sourceRows),
    evidence: structuredClone(value.evidence) }, close: async () => { closed.push('source'); } }),
  target: async () => ({ value: { events: events(targetRows), evidence: structuredClone(value.evidence) },
    close: async () => { closed.push('target'); } }),
  reconciliationKey: async () => ({ value: RECONCILIATION_KEY,
    close: async () => { closed.push('key'); } }), ...overrides } };
}

async function runtime(value, sourceRows, targetRows, overrides = {}) {
  const plan = await planM4Reconciliation(value.serial); const made = factories(value, sourceRows, targetRows, overrides.factories);
  return { plan, made, input: { ...value.serial, confirmedPlanDigest: plan.confirmationDigest,
    verifyCurrentLegacyCompletion: overrides.verifyLegacy ?? (async () => value.legacy),
    verifyCurrentNativePhaseCompletion: overrides.verifyNative ?? (async () => value.native),
    factories: made.value } };
}

test('exact comparison produces independently verifiable complete evidence', async () => {
  const value = fixture(); const row = event(1); const ready = await runtime(value, [row], [row]);
  const result = await runM4Reconciliation(ready.input);
  assert.equal(result.report.state, 'complete'); assert.equal(result.manifest.reconciliation.state, 'complete');
  assert.deepEqual(verifyM4ReconciliationManifest(result.manifest, RECONCILIATION_KEY), result.manifest);
  assert.deepEqual(ready.made.closed, ['key', 'target', 'source']);
});

test('mismatches remain a truthful signed pending manifest', async () => {
  const value = fixture(); const ready = await runtime(value, [event(1)], [event(2)]);
  const result = await runM4Reconciliation(ready.input);
  assert.equal(result.report.state, 'pending'); assert.ok(result.report.unresolvedMismatchCount > 0);
  assert.equal(result.manifest.reconciliation.state, 'pending');
  assert.deepEqual(verifyM4ReconciliationManifest(result.manifest, RECONCILIATION_KEY), result.manifest);
});

test('wrong confirmation and changed current evidence fail before factories or signing', async () => {
  const value = fixture(); const ready = await runtime(value, [event(1)], [event(1)]);
  let currentCalls = 0; let factoryCalls = 0;
  const guarded = Object.fromEntries(Object.entries(ready.input.factories).map(([name, factory]) => [name,
    async context => { factoryCalls += 1; return factory(context); }]));
  await assert.rejects(() => runM4Reconciliation({ ...ready.input,
    confirmedPlanDigest: sha('wrong'), factories: guarded,
    verifyCurrentLegacyCompletion: async () => { currentCalls += 1; return value.legacy; } }),
  { code: 'm4_reconciliation_runner_confirmation_invalid' });
  assert.equal(currentCalls, 0); assert.equal(factoryCalls, 0);
  const changed = structuredClone(value.native); changed.receiptDigest = sha('changed');
  await assert.rejects(() => runM4Reconciliation({ ...ready.input, factories: guarded,
    verifyCurrentNativePhaseCompletion: async () => changed }),
  { code: 'm4_reconciliation_runner_prerequisite_unverified' });
  assert.equal(factoryCalls, 0);
});

test('operator-confirmed static evidence cannot be substituted by a reader', async () => {
  const value = fixture(); const changed = staticEvidence();
  changed.pausedInterval.end = checkpoint('other-end-runner');
  let iterated = false;
  const ready = await runtime(value, [], [], { factories: { source: async () => ({ value: {
    events: { async *[Symbol.asyncIterator]() { iterated = true; } }, evidence: changed }, close: null }) } });
  await assert.rejects(() => runM4Reconciliation(ready.input),
    { code: 'm4_reconciliation_runner_evidence_mismatch' });
  assert.equal(iterated, false);
});

test('valid but differently linked completion evidence is rejected while planning', async () => {
  const value = fixture();
  const otherLegacy = legacyCompletion('other-legacy-authority');
  const otherNative = nativeCompletion(value.serial.gateInput, otherLegacy);
  await assert.rejects(() => planM4Reconciliation({ ...value.serial,
    nativePhaseCompletion: otherNative }),
  { code: 'm4_reconciliation_runner_prerequisite_mismatch' });
});

test('post-scan prerequisite drift blocks reconciliation key access', async () => {
  const value = fixture(); let checks = 0; let keyCalls = 0;
  const changed = nativeCompletion(value.serial.gateInput, value.legacy, 'changed-receipts');
  const ready = await runtime(value, [event(1)], [event(1)], {
    verifyNative: async () => { checks += 1; return checks === 1 ? value.native : changed; },
    factories: { reconciliationKey: async () => { keyCalls += 1;
      return { value: RECONCILIATION_KEY, close: null }; } },
  });
  await assert.rejects(() => runM4Reconciliation(ready.input),
    { code: 'm4_reconciliation_runner_prerequisite_changed' });
  assert.equal(checks, 2); assert.equal(keyCalls, 0);
});

test('reconciliation signing authority rejects identical and zero-padded completion keys', async () => {
  for (const document of [
    { ...LEGACY_KEY, keyId: RECONCILIATION_KEY.keyId },
    { schema: LEGACY_KEY.schema, keyId: RECONCILIATION_KEY.keyId,
      key: Buffer.concat([Buffer.from(LEGACY_KEY.key, 'base64'), Buffer.from([0])]).toString('base64') },
  ]) {
    const value = fixture(); const ready = await runtime(value, [event(1)], [event(1)], {
      factories: { reconciliationKey: async () => ({ value: document, close: null }) },
    });
    await assert.rejects(() => runM4Reconciliation(ready.input),
      { code: 'm4_reconciliation_runner_key_separation_invalid' });
  }
});

test('completion authorities themselves must be HMAC-independent', async () => {
  const value = fixture();
  const equivalentNativeKey = { schema: LEGACY_KEY.schema, keyId: NATIVE_KEY.keyId,
    key: Buffer.concat([Buffer.from(LEGACY_KEY.key, 'base64'), Buffer.from([0])]).toString('base64') };
  const native = structuredClone(value.native);
  const payload = Object.fromEntries(Object.entries(native).filter(([name]) => name !== 'evidence'));
  const evidenceDigest = sha({ schema: 'amf.m4-native-paused-phase-completion-evidence/v1',
    manifestId: native.evidence.manifestId, keyId: equivalentNativeKey.keyId, completion: payload });
  native.evidence = { ...native.evidence, keyId: equivalentNativeKey.keyId, digest: evidenceDigest,
    signature: sign(equivalentNativeKey,
      'amf.m4-native-paused-phase-completion/v1/integrity', evidenceDigest) };
  await assert.rejects(() => planM4Reconciliation({ ...value.serial,
    nativePhaseCompletion: native, nativePhaseCompletionKeyDocument: equivalentNativeKey }),
  { code: 'm4_reconciliation_runner_key_separation_invalid' });
});

test('primary failures survive cleanup failures and cleanup-only failure is stable', async () => {
  const value = fixture(); const first = await runtime(value, [event(1)], [event(1)], { factories: {
    source: async () => ({ value: { events: events([event(1)]), evidence: value.evidence },
      close: async () => { throw new Error('cleanup'); } }),
    target: async () => { throw new Error('target'); },
  } });
  await assert.rejects(() => runM4Reconciliation(first.input),
    { code: 'm4_reconciliation_runner_target_factory_failed' });

  const second = await runtime(value, [event(1)], [event(1)], { factories: {
    reconciliationKey: async () => ({ value: RECONCILIATION_KEY,
      close: async () => { throw new Error('cleanup'); } }),
  } });
  await assert.rejects(() => runM4Reconciliation(second.input),
    { code: 'm4_reconciliation_runner_cleanup_failed' });
});

test('planning enforces the published visit and mismatch-sample bounds', async () => {
  const value = fixture();
  await assert.rejects(() => planM4Reconciliation({ ...value.serial, maxVisitedEvents: 0 }),
    { code: 'm4_reconciliation_runner_plan_input_invalid' });
  await assert.rejects(() => planM4Reconciliation({ ...value.serial, maxMismatchSamples: 1001 }),
    { code: 'm4_reconciliation_runner_plan_input_invalid' });
});

test('hostile serial and confirmation getters normalize without runtime access', async () => {
  const value = fixture(); const ready = await runtime(value, [], []); let factoryCalls = 0;
  const hostileSerial = { ...ready.input };
  Object.defineProperty(hostileSerial, 'manifestId', { enumerable: true,
    get() { throw new Error('private serial detail'); } });
  await assert.rejects(() => runM4Reconciliation(hostileSerial),
    { code: 'm4_reconciliation_runner_run_input_invalid' });

  const hostileConfirmation = { ...ready.input,
    factories: Object.fromEntries(Object.entries(ready.input.factories).map(([name, factory]) => [name,
      async context => { factoryCalls += 1; return factory(context); }])) };
  Object.defineProperty(hostileConfirmation, 'confirmedPlanDigest', { enumerable: true,
    get() { throw new Error('private confirmation detail'); } });
  await assert.rejects(() => runM4Reconciliation(hostileConfirmation),
    { code: 'm4_reconciliation_runner_run_input_invalid' });
  assert.equal(factoryCalls, 0);
});

test('hostile signing-key documents are typed and their resource is closed', async () => {
  const value = fixture(); const closed = [];
  const hostileKey = { schema: RECONCILIATION_KEY.schema, keyId: RECONCILIATION_KEY.keyId };
  Object.defineProperty(hostileKey, 'key', { enumerable: true,
    get() { throw new Error('private key provider detail'); } });
  const ready = await runtime(value, [event(1)], [event(1)], { factories: {
    source: async () => ({ value: { events: events([event(1)]), evidence: value.evidence },
      close: async () => { closed.push('source'); } }),
    target: async () => ({ value: { events: events([event(1)]), evidence: value.evidence },
      close: async () => { closed.push('target'); } }),
    reconciliationKey: async () => ({ value: hostileKey,
      close: async () => { closed.push('key'); } }),
  } });
  await assert.rejects(() => runM4Reconciliation(ready.input),
    { code: 'm4_reconciliation_runner_key_invalid' });
  assert.deepEqual(closed, ['key', 'target', 'source']);
});
