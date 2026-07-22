import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { SqliteConversationArchive } from '../src/conversation-archive-v1.mjs';
import { ConversationEventPlaintextOutbox } from '../src/ingest/conversation-event-v3-outbox.mjs';
import { canonicalJson } from '../src/ingest/transcripts/canonical.mjs';
import { aggregatePauseCheckpointInputs, createPauseManifest } from '../src/migration-pause.mjs';
import { createM4RollbackManifest, verifyM4BackfillGate } from '../src/migration/m4-backfill-gate.mjs';
import {
  deriveM4NativePausedRunId,
  planM4NativePausedBatch,
  runM4NativePausedBatch,
} from '../src/migration/m4-native-paused-batch-runner.mjs';
import { M4ProgressStore } from '../src/migration/m4-progress-store.mjs';

const EVENT_KEY = Buffer.alloc(32, 7);
const DERIVATION_KEY = Buffer.alloc(32, 3);
const digest = value => `sha256:${crypto.createHash('sha256').update(String(value)).digest('hex')}`;
const checkpoint = (id, value = id) => ({ id, digest: digest(value) });
const keyDocument = (id, byte) => ({ schema: 'amf.migration-signing-key/v1', keyId: id,
  key: Buffer.alloc(32, byte).toString('base64') });

function gateFixture() {
  const pauseKey = keyDocument('native-pause-key', 10);
  const rollbackKey = keyDocument('native-rollback-key', 11);
  const collector = `pause-collector-${'1'.repeat(64)}`;
  const pauseInput = {
    schema: 'amf.migration-pause-checkpoints/v1',
    manifestId: 'pause-manifest-native',
    revision: 1,
    keyId: pauseKey.keyId,
    pause: {
      state: 'paused',
      collectorCursor: checkpoint('collector-cursor-native'),
      pendingOutbox: checkpoint('pending-outbox-native'),
      acknowledgements: checkpoint('acknowledgements-native'),
      deadLetters: checkpoint('dead-letters-native'),
      sourceCheckpoint: checkpoint('source-checkpoint-native'),
      nativeTranscriptAuthority: checkpoint('native-authority-native'),
      evidence: checkpoint(collector),
    },
  };
  const roster = { schema: 'amf.migration-pause-collector-roster/v1', manifestId: pauseInput.manifestId,
    revision: pauseInput.revision, keyId: pauseKey.keyId, collectors: [collector] };
  const pauseManifest = createPauseManifest(aggregatePauseCheckpointInputs([pauseInput], roster), pauseKey);
  const rollbackManifest = createM4RollbackManifest({ schema: 'amf.migration-manifest/v1',
    manifestId: 'rollback-manifest-native', phase: 'rollback', revision: 1,
    rollback: {
      pauseEvidence: { manifestId: pauseManifest.manifestId, digest: pauseManifest.integrity.payloadDigest,
        signature: pauseManifest.integrity.signature },
      sourceCheckpoint: pauseManifest.pause.sourceCheckpoint,
      targetCheckpoint: checkpoint('target-checkpoint-native'),
      compatibilityRouteRevision: 'compatibility-route-native',
      recoveryCopy: checkpoint('recovery-copy-native'),
      restoreTest: 'passed',
    } }, rollbackKey);
  return { pauseManifest, pauseKeyDocument: pauseKey, rollbackManifest, rollbackKeyDocument: rollbackKey };
}

function authorityFor(gateFiles, interval = { startExclusive: 0, endInclusive: 1,
  chain: checkpoint('native-chain-one') }) {
  const gate = verifyM4BackfillGate({ runId: 'temporary-native-run', phase: 'paused-native', ...gateFiles });
  const sourceBinding = `hmac-sha256:source-v1:${crypto.createHmac('sha256', DERIVATION_KEY)
    .update(canonicalJson(['amf.m4-native-paused/tag/source-v1/v1', 'codex', 'source-one']), 'utf8').digest('hex')}`;
  return { schema: 'amf.m4-native-paused-interval-authority/v1', pauseEvidence: gate.pauseEvidence,
    source: gateFiles.pauseManifest.pause.nativeTranscriptAuthority, sourceBinding, interval,
    initialCheckpoint: gate.sourceCheckpoint };
}

function legacyCompletion(value = 'one') {
  return { schema: 'amf.m4-legacy-group-replay-completion/v1', state: 'complete',
    authorityDigest: digest(`legacy-authority-${value}`), checkpoint: checkpoint(`legacy-checkpoint-${value}`),
    evidence: { manifestId: `legacy-manifest-${value}`, digest: digest(`legacy-evidence-${value}`),
      signature: Buffer.alloc(32, value.charCodeAt(0)).toString('base64url') } };
}

function gateInput(gateFiles, authority, completion) {
  return { runId: deriveM4NativePausedRunId(authority, completion), phase: 'paused-native', ...gateFiles };
}

function reader(authority, { openError = null } = {}) {
  const records = Array.from({ length: authority.interval.endInclusive - authority.interval.startExclusive }, (_, index) => {
    const position = authority.interval.startExclusive + index + 1;
    const timestamp = `2026-07-22T00:00:${String(position).padStart(2, '0')}Z`;
    const messageId = `message-${position}`;
    return { native: { runtime: 'codex', sourceId: 'source-one', conversationId: 'session-one',
      threadId: null, messageId, position, sourceOccurredAt: timestamp }, sessionHint: 'session-one',
    value: { type: 'response_item', session_id: 'session-one', id: messageId, timestamp,
      payload: { type: 'message', role: 'user', content: [{ type: 'input_text', text: `hello ${position}` }] } } };
  });
  return { async open(input) {
    if (openError) throw openError;
    assert.deepEqual(input, { schema: authority.schema, source: authority.source, interval: authority.interval });
    return { schema: 'amf.m4-native-paused-reader/v1', source: authority.source, interval: authority.interval,
      runtime: 'codex', sourceId: 'source-one', records: (async function* () { yield* records; })(),
      completion: async () => ({ schema: 'amf.m4-native-paused-completion/v1', source: authority.source,
        endInclusive: authority.interval.endInclusive, chain: authority.interval.chain }) };
  } };
}

function legacyVerifier(completion, calls = null) {
  return async () => { if (calls) calls.push('legacy'); return completion; };
}

function pauseVerifier(authority, calls = null) {
  return async () => {
    if (calls) calls.push('pause');
    return { pauseEvidence: authority.pauseEvidence, nativeTranscriptAuthority: authority.source,
      sourceCheckpoint: authority.initialCheckpoint };
  };
}

function factories(root, calls) {
  return {
    lease: async () => { calls.push('lease'); return { async acquire() {}, async heartbeat() {}, async release() {} }; },
    outbox: async () => { calls.push('outbox'); return new ConversationEventPlaintextOutbox({
      rootPath: path.join(root, 'outbox'), resolveIntegrityKey: keyId => keyId === 'event-k1' ? EVENT_KEY : null,
      clock: () => Date.parse('2026-07-22T00:01:00Z'), nonceFactory: () => 'deliverynonce000001' }); },
    archive: async () => { calls.push('archive'); return { archive: new SqliteConversationArchive({
      filename: path.join(root, 'archive.sqlite'), resolveIntegrityKey: keyId => keyId === 'event-k1' ? EVENT_KEY : null,
      resolveExpiresAt: () => '2027-07-22T00:00:00Z', cursorKey: Buffer.alloc(32, 4) }),
    resolveIntegrityKey: keyId => keyId === 'event-k1' ? EVENT_KEY : null }; },
    checkpointStore: async input => { calls.push('checkpoint'); return new M4ProgressStore({ rootPath: path.join(root, 'progress'),
      runId: input.runId, phase: input.phase, planDigest: input.planDigest }); },
  };
}

function runInput(gateFiles, authority, completion, plan, root, calls) {
  return { gateInput: gateInput(gateFiles, authority, completion), maxEvents: 1, authority,
    legacyCompletion: completion,
    confirmedPlanDigest: plan.confirmationDigest, reader: reader(authority),
    derivationKey: DERIVATION_KEY, derivationKeyId: 'native-test-k1',
    verifyPauseEvidence: pauseVerifier(authority, calls),
    verifyLegacyCompletion: legacyVerifier(completion, calls),
    integrityFor: async () => ({ keyId: 'event-k1', key: EVENT_KEY,
      sentAt: '2026-07-22T00:00:30Z', nonce: 'eventnonce0000001' }), factories: factories(root, calls) };
}

test('plans without resources, runs one real paused-native shard, and resumes its isolated progress', async () => {
  const gateFiles = gateFixture(); const authority = authorityFor(gateFiles); const completion = legacyCompletion();
  const input = { gateInput: gateInput(gateFiles, authority, completion), maxEvents: 1, authority, legacyCompletion: completion };
  const plan = await planM4NativePausedBatch(input);
  assert.deepEqual(Object.keys(plan), ['schema', 'operation', 'runId', 'phase', 'maxEvents', 'authorityDigest', 'legacyCompletionDigest', 'confirmationDigest']);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-native-batch-')); const calls = [];
  try {
    const first = await runM4NativePausedBatch(runInput(gateFiles, authority, completion, plan, root, calls));
    assert.equal(first.processed, 1); assert.equal(first.complete, true); assert.equal(first.phase, 'paused-native');
    assert.equal(first.legacyCompletionDigest, plan.legacyCompletionDigest);
    assert.deepEqual(calls, ['legacy', 'pause', 'lease', 'outbox', 'archive', 'checkpoint', 'pause']);
    const secondCalls = [];
    const second = await runM4NativePausedBatch(runInput(gateFiles, authority, completion, plan, root, secondCalls));
    assert.equal(second.processed, 0); assert.equal(second.complete, true);
    const archive = new SqliteConversationArchive({ filename: path.join(root, 'archive.sqlite'),
      resolveIntegrityKey: keyId => keyId === 'event-k1' ? EVENT_KEY : null,
      resolveExpiresAt: () => '2027-07-22T00:00:00Z', cursorKey: Buffer.alloc(32, 4) });
    assert.equal(archive.db.prepare('SELECT COUNT(*) AS count FROM conversation_archive_events_v1').get().count, 1);
    archive.close();
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('confirmation and pause evidence fail before any resource factory', async () => {
  const gateFiles = gateFixture(); const authority = authorityFor(gateFiles); const completion = legacyCompletion();
  const plan = await planM4NativePausedBatch({ gateInput: gateInput(gateFiles, authority, completion), maxEvents: 1, authority, legacyCompletion: completion });
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-native-batch-')); const calls = [];
  try {
    const wrong = runInput(gateFiles, authority, completion, plan, root, calls); wrong.confirmedPlanDigest = digest('wrong');
    await assert.rejects(() => runM4NativePausedBatch(wrong), { code: 'm4_native_batch_confirmation_invalid' });
    assert.deepEqual(calls, []);
    const mismatch = runInput(gateFiles, authority, completion, plan, root, calls);
    mismatch.verifyPauseEvidence = async () => ({ pauseEvidence: authority.pauseEvidence,
      nativeTranscriptAuthority: checkpoint('other-native-authority'), sourceCheckpoint: authority.initialCheckpoint });
    await assert.rejects(() => runM4NativePausedBatch(mismatch), { code: 'm4_native_batch_pause_mismatch' });
    assert.deepEqual(calls, ['legacy']);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('plan binds the paused phase, exact gate evidence, authority, and one run namespace per shard', async () => {
  const gateFiles = gateFixture(); const completion = legacyCompletion(); const first = authorityFor(gateFiles);
  const second = authorityFor(gateFiles, { startExclusive: 1, endInclusive: 2, chain: checkpoint('native-chain-two') });
  assert.notEqual(deriveM4NativePausedRunId(first, completion), deriveM4NativePausedRunId(second, completion));
  const firstPlan = await planM4NativePausedBatch({ gateInput: gateInput(gateFiles, first, completion), maxEvents: 1, authority: first, legacyCompletion: completion });
  const secondPlan = await planM4NativePausedBatch({ gateInput: gateInput(gateFiles, second, completion), maxEvents: 1, authority: second, legacyCompletion: completion });
  assert.notEqual(firstPlan.confirmationDigest, secondPlan.confirmationDigest);
  await assert.rejects(() => planM4NativePausedBatch({ gateInput: { ...gateInput(gateFiles, first, completion), phase: 'v2-archive' },
    maxEvents: 1, authority: first, legacyCompletion: completion }), { code: 'm4_native_batch_gate_mismatch' });
  await assert.rejects(() => planM4NativePausedBatch({ gateInput: { ...gateInput(gateFiles, first, completion), runId: 'wrong-native-run' },
    maxEvents: 1, authority: first, legacyCompletion: completion }), { code: 'm4_native_batch_gate_mismatch' });
  await assert.rejects(() => planM4NativePausedBatch({ gateInput: gateInput(gateFiles, first, completion), maxEvents: 1,
    authority: { ...first, initialCheckpoint: checkpoint('other-source-checkpoint') }, legacyCompletion: completion }),
  { code: 'm4_native_batch_gate_mismatch' });
});

test('snapshots reader, factory, and pause-attestation getters once', async () => {
  const gateFiles = gateFixture(); const authority = authorityFor(gateFiles); const completion = legacyCompletion();
  const plan = await planM4NativePausedBatch({ gateInput: gateInput(gateFiles, authority, completion), maxEvents: 1, authority, legacyCompletion: completion });
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-native-batch-')); const calls = [];
  try {
    const input = runInput(gateFiles, authority, completion, plan, root, calls);
    const counts = { reader: 0, pause: 0, lease: 0, outbox: 0, archive: 0, checkpointStore: 0 };
    const originalReader = input.reader;
    input.reader = Object.defineProperty({}, 'open', { enumerable: true, get() {
      counts.reader += 1; return originalReader.open;
    } });
    const originalFactories = input.factories;
    input.factories = Object.defineProperties({}, Object.fromEntries(Object.entries(originalFactories)
      .map(([name, factory]) => [name, { enumerable: true, get() { counts[name] += 1; return factory; } }])));
    input.verifyPauseEvidence = async () => Object.defineProperties({}, {
      pauseEvidence: { enumerable: true, get() { counts.pause += 1; return authority.pauseEvidence; } },
      nativeTranscriptAuthority: { enumerable: true, get() { counts.pause += 1; return authority.source; } },
      sourceCheckpoint: { enumerable: true, get() { counts.pause += 1; return authority.initialCheckpoint; } },
    });
    await runM4NativePausedBatch(input);
    assert.deepEqual(counts, { reader: 1, pause: 6, lease: 1, outbox: 1, archive: 1, checkpointStore: 1 });
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('binds the authenticated native authority and legacy completion into the plan', async () => {
  const gateFiles = gateFixture(); const completion = legacyCompletion(); const authority = authorityFor(gateFiles);
  const substituted = { ...authority, source: checkpoint('substituted-native-authority') };
  await assert.rejects(() => planM4NativePausedBatch({
    gateInput: gateInput(gateFiles, substituted, completion), maxEvents: 1,
    authority: substituted, legacyCompletion: completion,
  }), { code: 'm4_native_batch_gate_mismatch' });
  const otherCompletion = legacyCompletion('two');
  assert.notEqual(deriveM4NativePausedRunId(authority, completion), deriveM4NativePausedRunId(authority, otherCompletion));
  const first = await planM4NativePausedBatch({ gateInput: gateInput(gateFiles, authority, completion),
    maxEvents: 1, authority, legacyCompletion: completion });
  const second = await planM4NativePausedBatch({ gateInput: gateInput(gateFiles, authority, otherCompletion),
    maxEvents: 1, authority, legacyCompletion: otherCompletion });
  assert.notEqual(first.confirmationDigest, second.confirmationDigest);
});

test('does not read runtime dependencies before confirmation and normalizes hostile getters', async () => {
  const gateFiles = gateFixture(); const completion = legacyCompletion(); const authority = authorityFor(gateFiles);
  const plan = await planM4NativePausedBatch({ gateInput: gateInput(gateFiles, authority, completion),
    maxEvents: 1, authority, legacyCompletion: completion });
  const input = { gateInput: gateInput(gateFiles, authority, completion), maxEvents: 1, authority,
    legacyCompletion: completion, confirmedPlanDigest: digest('wrong') };
  const dependencyNames = ['reader', 'derivationKey', 'derivationKeyId', 'verifyPauseEvidence',
    'verifyLegacyCompletion', 'integrityFor', 'factories'];
  let reads = 0;
  for (const name of dependencyNames) Object.defineProperty(input, name, { enumerable: true, get() {
    reads += 1; throw new Error('private getter detail');
  } });
  await assert.rejects(() => runM4NativePausedBatch(input), { code: 'm4_native_batch_confirmation_invalid' });
  assert.equal(reads, 0);
  input.confirmedPlanDigest = plan.confirmationDigest;
  await assert.rejects(() => runM4NativePausedBatch(input), error => error.code === 'm4_native_batch_dependency_invalid'
    && error.message === 'm4_native_batch_dependency_invalid');
  assert.equal(reads, 1);
});

test('requires current legacy completion before resource factories', async () => {
  const gateFiles = gateFixture(); const completion = legacyCompletion(); const authority = authorityFor(gateFiles);
  const plan = await planM4NativePausedBatch({ gateInput: gateInput(gateFiles, authority, completion),
    maxEvents: 1, authority, legacyCompletion: completion });
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-native-batch-')); const calls = [];
  try {
    const input = runInput(gateFiles, authority, completion, plan, root, calls);
    input.verifyLegacyCompletion = async () => legacyCompletion('two');
    await assert.rejects(() => runM4NativePausedBatch(input), { code: 'm4_native_batch_legacy_mismatch' });
    assert.deepEqual(calls, []);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('resumes a partial multi-event shard and isolates two shards in one progress root', async () => {
  const gateFiles = gateFixture(); const completion = legacyCompletion();
  const firstAuthority = authorityFor(gateFiles, { startExclusive: 0, endInclusive: 2,
    chain: checkpoint('native-chain-first') });
  const secondAuthority = authorityFor(gateFiles, { startExclusive: 2, endInclusive: 3,
    chain: checkpoint('native-chain-second') });
  const firstPlan = await planM4NativePausedBatch({ gateInput: gateInput(gateFiles, firstAuthority, completion),
    maxEvents: 1, authority: firstAuthority, legacyCompletion: completion });
  const secondPlan = await planM4NativePausedBatch({ gateInput: gateInput(gateFiles, secondAuthority, completion),
    maxEvents: 1, authority: secondAuthority, legacyCompletion: completion });
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-native-batch-'));
  try {
    const first = await runM4NativePausedBatch(runInput(gateFiles, firstAuthority, completion, firstPlan, root, []));
    assert.equal(first.processed, 1); assert.equal(first.complete, false);
    const resumed = await runM4NativePausedBatch(runInput(gateFiles, firstAuthority, completion, firstPlan, root, []));
    assert.equal(resumed.processed, 1); assert.equal(resumed.complete, true);
    const second = await runM4NativePausedBatch(runInput(gateFiles, secondAuthority, completion, secondPlan, root, []));
    assert.equal(second.processed, 1); assert.equal(second.complete, true);
    assert.notEqual(first.runId, second.runId);
    assert.equal(fs.readdirSync(path.join(root, 'progress')).length, 2);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('cleans resources and reports a stable error when the second pause verification fails', async () => {
  const gateFiles = gateFixture(); const completion = legacyCompletion(); const authority = authorityFor(gateFiles);
  const plan = await planM4NativePausedBatch({ gateInput: gateInput(gateFiles, authority, completion),
    maxEvents: 1, authority, legacyCompletion: completion });
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-native-batch-')); const closed = [];
  try {
    const input = runInput(gateFiles, authority, completion, plan, root, []);
    let pauseCalls = 0;
    input.verifyPauseEvidence = async () => {
      pauseCalls += 1;
      if (pauseCalls === 2) throw new Error('private verification failure');
      return { pauseEvidence: authority.pauseEvidence, nativeTranscriptAuthority: authority.source,
        sourceCheckpoint: authority.initialCheckpoint };
    };
    input.factories.lease = async () => ({ async acquire() {}, async heartbeat() {}, async release() {},
      async close() { closed.push('lease'); } });
    await assert.rejects(() => runM4NativePausedBatch(input), { code: 'm4_backfill_source_read_failed' });
    assert.deepEqual(closed, ['lease']);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
