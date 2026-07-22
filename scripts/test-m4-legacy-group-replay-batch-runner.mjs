import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { MemoryCatalog } from '../src/fabric-store.mjs';
import {
  ciphertextContentId,
  normalizeIngestKeyRing,
  normalizedObservationDigest,
} from '../src/ingest/raw-event-contract.mjs';
import { EncryptedOutbox } from '../src/ingest/outbox.mjs';
import {
  deriveEventIdV2,
  deriveLogicalMessageIds,
  deriveSessionIdV2,
  opaqueContextTag,
} from '../src/ingest/raw-projection-v2.mjs';
import { aggregatePauseCheckpointInputs, createPauseManifest } from '../src/migration-pause.mjs';
import { createM4RollbackManifest } from '../src/migration/m4-backfill-gate.mjs';
import { prepareM4V2UnifiedIndex } from '../src/migration/m4-v2-unified-index.mjs';
import {
  deriveM4LegacyGroupReplayRunId,
  planM4LegacyGroupReplayBatch,
  runM4LegacyGroupReplayBatch,
  verifyM4LegacyGroupReplayCompletion,
} from '../src/migration/m4-legacy-group-replay-batch-runner.mjs';

const EVENT_KEY = Buffer.alloc(32, 17);
const INGEST_KEY = Buffer.alloc(32, 7).toString('base64');
const LOGICAL_KEY = Buffer.alloc(32, 8).toString('base64');
const TAG_KEY = Buffer.alloc(32, 9).toString('base64');
const INGEST_KEYS = {
  keys: { ingest: INGEST_KEY }, digestKey: INGEST_KEY,
  authorizations: { ingest: { actors: ['synthetic-actor'], sourceInstances: ['synthetic-source'] } },
  logicalMessageKeys: { currentKeyVersion: 'logical-k1', keys: { 'logical-k1': LOGICAL_KEY } },
};
const DIGEST_KEY = normalizeIngestKeyRing(INGEST_KEYS).digestKey;
const AUTHORITY = { schema: 'amf.m4-group-replay-authority/v1', authorityDigest: sha('group-authority') };
const LIMITS = { maxGroups: 1, maxObservations: 10, maxOutputEvents: 10 };
const OWNER = `catalog-k1:${'a'.repeat(64)}`;
const SOURCE = `catalog-k1:${'b'.repeat(64)}`;

function sha(value) { return `sha256:${crypto.createHash('sha256').update(String(value)).digest('hex')}`; }
function checkpoint(id, value = id) { return { id, digest: sha(value) }; }
function keyDocument(id, byte) { return { schema: 'amf.migration-signing-key/v1', keyId: id,
  key: Buffer.alloc(32, byte).toString('base64') }; }
function tag(namespace, value) { return opaqueContextTag(namespace, value, TAG_KEY, 'routing-k1'); }

function gateFixture() {
  const pauseKeyDocument = keyDocument('legacy-pause-key', 10);
  const rollbackKeyDocument = keyDocument('legacy-rollback-key', 11);
  const collector = `pause-collector-${'1'.repeat(64)}`;
  const pauseInput = { schema: 'amf.migration-pause-checkpoints/v1', manifestId: 'pause-manifest-legacy',
    revision: 1, keyId: pauseKeyDocument.keyId, pause: { state: 'paused',
      collectorCursor: checkpoint('collector-cursor-legacy'), pendingOutbox: checkpoint('pending-outbox-legacy'),
      acknowledgements: checkpoint('acknowledgements-legacy'), deadLetters: checkpoint('dead-letters-legacy'),
      sourceCheckpoint: checkpoint('source-checkpoint-legacy'),
      nativeTranscriptAuthority: checkpoint('native-authority-legacy'), evidence: checkpoint(collector) } };
  const roster = { schema: 'amf.migration-pause-collector-roster/v1', manifestId: pauseInput.manifestId,
    revision: pauseInput.revision, keyId: pauseKeyDocument.keyId, collectors: [collector] };
  const pauseManifest = createPauseManifest(aggregatePauseCheckpointInputs([pauseInput], roster), pauseKeyDocument);
  const rollbackManifest = createM4RollbackManifest({ schema: 'amf.migration-manifest/v1',
    manifestId: 'rollback-manifest-legacy', phase: 'rollback', revision: 1, rollback: {
      pauseEvidence: { manifestId: pauseManifest.manifestId, digest: pauseManifest.integrity.payloadDigest,
        signature: pauseManifest.integrity.signature }, sourceCheckpoint: pauseManifest.pause.sourceCheckpoint,
      targetCheckpoint: checkpoint('target-checkpoint-legacy'), compatibilityRouteRevision: 'compatibility-route-legacy',
      recoveryCopy: checkpoint('recovery-copy-legacy'), restoreTest: 'passed' } }, rollbackKeyDocument);
  return { pauseManifest, pauseKeyDocument, rollbackManifest, rollbackKeyDocument };
}

function serial(overrides = {}) {
  return { authority: AUTHORITY, limits: LIMITS, maxBatches: 1,
    completionManifestId: 'legacy-replay-completion', completionKeyId: 'legacy-completion-key', ...overrides };
}

function gateInput(gateFiles, accepted) {
  return { runId: deriveM4LegacyGroupReplayRunId(accepted), phase: 'v2-archive', ...gateFiles };
}

function v2Item(suffix) {
  const senderTag = tag('sender', 'synthetic-sender'); const conversationTag = tag('conversation', `conversation-${suffix}`);
  const logical = { canonicalSenderIdentity: 'synthetic-sender', senderTag, conversationTag,
    direction: 'inbound', nativePlatform: 'synthetic-platform', nativeConversationId: `conversation-${suffix}`,
    nativeMessageId: `message-${suffix}` };
  const ids = deriveLogicalMessageIds(logical, INGEST_KEYS.logicalMessageKeys);
  const rawBytes = Buffer.from(`native-raw-${suffix}`, 'utf8');
  const eventId = deriveEventIdV2({ sourceKind: 'codex', observationClass: 'native', rawBytes });
  const sessionId = deriveSessionIdV2({ sourceKind: 'codex', conversationTag });
  const normalized = { role: 'user', contentType: 'text', value: `visible synthetic ${suffix}` };
  const occurredAt = '2026-07-22T00:00:01.000000000Z';
  const event = { schema: 'amf.raw-event/v2', eventId, sessionId, occurredAt,
    source: { runtime: 'codex', subtype: 'message' }, logical, normalized,
    raw: { encoding: 'base64', line: rawBytes.toString('base64'), lineEnding: 'lf' } };
  const projection = { schema: 'amf.raw-event-projection/v2', eventId, sessionId,
    logicalMessageId: ids.logicalMessageId, logicalMessageAliases: ids.aliases,
    derivationVersion: 'amf-logical-message/v1', keyVersion: ids.keyVersion,
    sourceKind: 'codex', observationClass: 'native', direction: 'inbound', conversationKind: 'dm',
    contextTags: { actor: [tag('actor', 'synthetic-actor')], sender: [senderTag],
      conversation: [conversationTag], room: [tag('room', 'synthetic-room')] },
    subtype: 'message', occurredAt, editedAt: null, nativeRevision: 1, sourceSequence: 1,
    authoritativeDeletion: false, role: 'user', contentType: 'text', contentParts: 1,
    hasContent: true, normalizationVersion: 'amf-observation-normalization/v1',
    normalizedPayloadDigest: normalizedObservationDigest({ event }, DIGEST_KEY) };
  return { event, projection };
}

function encrypt(value) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-m4-legacy-encrypt-'));
  try {
    return new EncryptedOutbox({ rootPath: root, encryptionKey: INGEST_KEY, digestKey: INGEST_KEY,
      sourceInstanceId: 'synthetic-source', actorId: 'synthetic-actor', keyId: 'ingest' }).encrypt(value);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

async function v2IndexInput(values) {
  const catalog = new MemoryCatalog(); const envelopes = new Map();
  for (const value of values) {
    const envelope = encrypt(value); const contentId = ciphertextContentId(envelope);
    const row = { eventId: value.event.eventId, sessionId: value.event.sessionId,
      logicalMessageId: value.projection.logicalMessageId, contentId, payloadDigest: envelope.payloadDigest,
      projection: structuredClone(value.projection), ownerTag: OWNER, sourceTag: SOURCE,
      createdAt: '2026-07-22T00:00:10Z' };
    envelopes.set(contentId, envelope);
    await catalog.ingestRawEventV2(row, { contentId, mediaType: 'application/json', byteLength: 1,
      storageRef: `synthetic/${contentId}`, createdAt: row.createdAt },
    { id: `audit-${row.eventId.slice(4, 36)}`, ts: row.createdAt, actorTag: OWNER,
      action: 'synthetic', targetId: row.eventId, details: {} });
  }
  return { catalog, rawStore: { async getClientCiphertext(contentId) { return structuredClone(envelopes.get(contentId)); } },
    ingestKeys: INGEST_KEYS, verifyCatalogBinding: async () => ({ owner: true, source: true }),
    auditDecrypt: async request => ({ recorded: true, eventId: request.eventId, contentId: request.contentId }),
    pageLimit: 1 };
}

function preservedIndexInput(pause) {
  const source = (kind, pauseCheckpoint) => ({ pauseCheckpoint,
    interval: { startExclusive: 0, endInclusive: 0, chain: checkpoint(`chain-${kind}`) },
    initialCheckpoint: checkpoint(`initial-${kind}`) });
  const authority = { acknowledgements: pause.acknowledgements,
    sources: { outbox: source('outbox', pause.pendingOutbox),
      deadletter: source('deadletter', pause.deadLetters) } };
  return { reader: { authority: () => structuredClone(authority), open(request) {
    return { schema: 'amf.m4-preserved-replay-reader/v2', sourceKind: request.sourceKind,
      pauseCheckpoint: structuredClone(request.pauseCheckpoint), interval: structuredClone(request.interval),
      records: (async function* () {})(), completion: async () => ({
        schema: 'amf.m4-preserved-replay-completion/v2', sourceKind: request.sourceKind,
        pauseCheckpoint: structuredClone(request.pauseCheckpoint), endInclusive: request.interval.endInclusive,
        chain: structuredClone(request.interval.chain) }) };
  }, openPositions() { throw new Error('no preserved records'); } },
  decoder: { index() { throw new Error('no preserved records'); }, materialize() { throw new Error('no preserved records'); } },
  sourceTag: `migration:${'a'.repeat(64)}` };
}

class Checkpoints {
  constructor() { this.value = null; }
  async load() { return structuredClone(this.value); }
  async commit(value) { this.value = structuredClone(value); return structuredClone(value); }
}

class Outbox {
  constructor({ conflict = false } = {}) { this.conflict = conflict; this.events = new Map(); this.deliveries = 0; this.duplicates = 0; }
  async enqueue(event) {
    if (this.conflict) return { eventId: event.eventId, payloadDigest: event.integrity.payloadDigest,
      state: 'conflict', duplicate: false };
    const prior = this.events.get(event.eventId);
    if (prior === event.integrity.payloadDigest) { this.duplicates += 1; return {
      eventId: event.eventId, payloadDigest: prior, state: 'acknowledged', duplicate: true };
    }
    if (prior !== undefined) return { eventId: event.eventId, payloadDigest: event.integrity.payloadDigest,
      state: 'conflict', duplicate: false };
    this.events.set(event.eventId, event.integrity.payloadDigest);
    return { eventId: event.eventId, payloadDigest: event.integrity.payloadDigest, state: 'pending', duplicate: false };
  }
  async deliver(eventId, sink) {
    this.deliveries += 1; const payloadDigest = this.events.get(eventId);
    await sink.deliver({ eventId, integrity: { payloadDigest } }, { idempotencyKey: eventId, payloadDigest });
    return { eventId, payloadDigest, state: 'acknowledged', duplicate: false };
  }
}

function replayValue(outbox, checkpoints) {
  return { outbox, checkpointStore: checkpoints, sink: { async deliver() { return {}; } },
    integrityFor: async ({ eventId, state, revision }) => ({ keyId: 'event-k1', key: EVENT_KEY,
      sentAt: '2026-07-22T00:01:00Z', nonce: `${state}${revision}${eventId.slice(5, 20)}`.padEnd(22, '0').slice(0, 22) }) };
}

async function setup(values, options = {}) {
  const gateFiles = gateFixture(); const accepted = serial(options.serial); const completionKey = keyDocument('legacy-completion-key', 12);
  const planInput = { gateInput: gateInput(gateFiles, accepted), ...accepted };
  const plan = await planM4LegacyGroupReplayBatch(planInput); const calls = options.calls ?? [];
  const v2 = await v2IndexInput(values); const outbox = options.outbox ?? new Outbox();
  const expectedV2 = await prepareM4V2UnifiedIndex({ ...v2, authority: AUTHORITY });
  const checkpoints = options.checkpoints ?? new Checkpoints();
  const factories = {
    v2Index: async () => { calls.push('v2'); return { value: v2, close: () => calls.push('close-v2') }; },
    preservedIndex: async () => { calls.push('preserved'); return { value: preservedIndexInput(gateFiles.pauseManifest.pause), close: () => calls.push('close-preserved') }; },
    replay: async () => { calls.push('replay'); return { value: replayValue(outbox, checkpoints), close: () => calls.push('close-replay') }; },
    completionKey: async () => { calls.push('key'); return { value: completionKey, close: () => calls.push('close-key') }; },
  };
  const runInput = { ...planInput, confirmedPlanDigest: plan.confirmationDigest,
    verifyV2Snapshot: async () => ({ sourceCheckpoint: gateFiles.rollbackManifest.rollback.sourceCheckpoint,
      targetCheckpoint: gateFiles.rollbackManifest.rollback.targetCheckpoint,
      indexAttestation: expectedV2.attestation }),
    resolveCanonicalLogicalId: async ({ logicalMessageIds }) => [...logicalMessageIds].sort()[0], factories };
  return { gateFiles, accepted, plan, runInput, calls, outbox, checkpoints, completionKey };
}

test('plans without factories, composes the real unified indexes, resumes, and signs completion only at EOF', async () => {
  const setupValue = await setup([v2Item('one'), v2Item('two')]);
  assert.deepEqual(Object.keys(setupValue.plan), ['schema', 'operation', 'runId', 'phase', 'authorityDigest',
    'gateDigest', 'limits', 'maxBatches', 'completionManifestId', 'completionKeyId', 'confirmationDigest']);
  const first = await runM4LegacyGroupReplayBatch(setupValue.runInput);
  assert.equal(first.groups, 1); assert.equal(first.complete, false); assert.equal(first.completion, null);
  assert.equal(setupValue.calls.includes('key'), false);
  const second = await runM4LegacyGroupReplayBatch(setupValue.runInput);
  assert.equal(second.groups, 1); assert.equal(second.complete, false); assert.equal(second.completion, null);
  assert.equal(setupValue.calls.includes('key'), false);
  const third = await runM4LegacyGroupReplayBatch(setupValue.runInput);
  assert.equal(third.groups, 0); assert.equal(third.complete, true);
  assert.deepEqual(verifyM4LegacyGroupReplayCompletion(third.completion, setupValue.completionKey), third.completion);
  assert.equal(JSON.stringify(third.completion).includes('visible synthetic'), false);
  assert.deepEqual(setupValue.calls.slice(-4), ['close-key', 'close-replay', 'close-v2', 'close-preserved']);
});

test('wrong confirmation reads no runtime dependency and hostile getters normalize after confirmation', async () => {
  const setupValue = await setup([v2Item('one')]);
  const input = { gateInput: setupValue.runInput.gateInput, authority: setupValue.accepted.authority,
    limits: setupValue.accepted.limits, maxBatches: setupValue.accepted.maxBatches,
    completionManifestId: setupValue.accepted.completionManifestId,
    completionKeyId: setupValue.accepted.completionKeyId, confirmedPlanDigest: sha('wrong') };
  let reads = 0;
  for (const name of ['verifyV2Snapshot', 'resolveCanonicalLogicalId', 'factories']) Object.defineProperty(input, name,
    { enumerable: true, get() { reads += 1; throw new Error('private getter'); } });
  await assert.rejects(() => runM4LegacyGroupReplayBatch(input), { code: 'm4_legacy_batch_confirmation_invalid' });
  assert.equal(reads, 0);
  input.confirmedPlanDigest = setupValue.plan.confirmationDigest;
  await assert.rejects(() => runM4LegacyGroupReplayBatch(input), error =>
    error.code === 'm4_legacy_batch_dependency_invalid' && error.message === error.code);
  assert.equal(reads, 1);
});

test('duplicate and conflict terminal outcomes both permit complete replay evidence', async () => {
  const value = v2Item('terminal'); const sharedOutbox = new Outbox();
  const accepted = await setup([value], { outbox: sharedOutbox, checkpoints: new Checkpoints(),
    serial: { limits: { maxGroups: 100, maxObservations: 100, maxOutputEvents: 100 } } });
  const first = await runM4LegacyGroupReplayBatch(accepted.runInput);
  assert.equal(first.complete, true); assert.equal(sharedOutbox.deliveries, 1);
  const duplicate = await setup([value], { outbox: sharedOutbox, checkpoints: new Checkpoints(),
    serial: { limits: { maxGroups: 100, maxObservations: 100, maxOutputEvents: 100 } } });
  const duplicateResult = await runM4LegacyGroupReplayBatch(duplicate.runInput);
  assert.equal(duplicateResult.complete, true); assert.equal(sharedOutbox.duplicates, 1);
  assert.equal(sharedOutbox.deliveries, 1);
  const conflictOutbox = new Outbox({ conflict: true });
  const conflict = await setup([value], { outbox: conflictOutbox, checkpoints: new Checkpoints(),
    serial: { limits: { maxGroups: 100, maxObservations: 100, maxOutputEvents: 100 } } });
  const conflictResult = await runM4LegacyGroupReplayBatch(conflict.runInput);
  assert.equal(conflictResult.complete, true); assert.equal(conflictOutbox.deliveries, 0);
});

test('tampered gate and completion evidence fail closed with fixed errors', async () => {
  const setupValue = await setup([v2Item('one')]);
  const changedGate = { ...setupValue.runInput, gateInput: structuredClone(setupValue.runInput.gateInput) };
  changedGate.gateInput.rollbackManifest.rollback.restoreTest = 'failed';
  await assert.rejects(() => runM4LegacyGroupReplayBatch(changedGate), { code: 'm4_legacy_batch_gate_invalid' });
  const completedSetup = await setup([v2Item('complete')], { serial: {
    limits: { maxGroups: 100, maxObservations: 100, maxOutputEvents: 100 } } });
  const completed = await runM4LegacyGroupReplayBatch(completedSetup.runInput);
  const changed = structuredClone(completed.completion); changed.checkpoint.digest = sha('changed');
  await assert.rejects(async () => verifyM4LegacyGroupReplayCompletion(changed, completedSetup.completionKey),
    { code: 'm4_legacy_completion_digest_mismatch' });
  const signature = structuredClone(completed.completion); signature.evidence.signature = 'a'.repeat(43);
  await assert.rejects(async () => verifyM4LegacyGroupReplayCompletion(signature, completedSetup.completionKey),
    { code: 'm4_legacy_completion_signature_mismatch' });
});

test('binds live v2, preserved queue, and signing-key authorities before their dependent work', async () => {
  const snapshot = await setup([v2Item('snapshot')]);
  snapshot.runInput.verifyV2Snapshot = async actual => ({ sourceCheckpoint: checkpoint('other-source'),
    targetCheckpoint: snapshot.gateFiles.rollbackManifest.rollback.targetCheckpoint,
    indexAttestation: actual });
  await assert.rejects(() => runM4LegacyGroupReplayBatch(snapshot.runInput),
    { code: 'm4_legacy_batch_v2_snapshot_mismatch' });
  assert.deepEqual(snapshot.calls, ['preserved', 'v2', 'close-v2', 'close-preserved']);

  const substituted = await setup([v2Item('catalog-bound')]);
  const emptyV2 = await v2IndexInput([]);
  substituted.runInput.factories.v2Index = async () => { substituted.calls.push('v2');
    return { value: emptyV2, close: () => substituted.calls.push('close-v2') }; };
  await assert.rejects(() => runM4LegacyGroupReplayBatch(substituted.runInput),
    { code: 'm4_legacy_batch_v2_snapshot_mismatch' });
  assert.equal(substituted.calls.includes('replay'), false);

  const preserved = await setup([v2Item('preserved')]);
  preserved.runInput.factories.preservedIndex = async () => {
    preserved.calls.push('preserved');
    const value = preservedIndexInput(preserved.gateFiles.pauseManifest.pause);
    const attested = value.reader.authority(); attested.acknowledgements = checkpoint('other-acks');
    value.reader.authority = () => structuredClone(attested);
    return { value, close: () => preserved.calls.push('close-preserved') };
  };
  await assert.rejects(() => runM4LegacyGroupReplayBatch(preserved.runInput),
    { code: 'm4_legacy_batch_preserved_authority_mismatch' });
  assert.deepEqual(preserved.calls, ['preserved', 'close-preserved']);

  const key = await setup([v2Item('key')], { serial: {
    limits: { maxGroups: 100, maxObservations: 100, maxOutputEvents: 100 },
    completionKeyId: 'other-completion-key' } });
  await assert.rejects(() => runM4LegacyGroupReplayBatch(key.runInput),
    { code: 'm4_legacy_batch_completion_key_mismatch' });
});

test('factory failure and invalid input close created resources in reverse order without leaking details', async () => {
  const calls = []; const setupValue = await setup([v2Item('one')], { calls });
  setupValue.runInput.factories.replay = async () => { calls.push('replay'); throw new Error('private resource detail'); };
  await assert.rejects(() => runM4LegacyGroupReplayBatch(setupValue.runInput), error =>
    error.code === 'm4_legacy_batch_replay_factory_failed' && error.message === error.code);
  assert.deepEqual(calls, ['preserved', 'v2', 'replay', 'close-v2', 'close-preserved']);
});
