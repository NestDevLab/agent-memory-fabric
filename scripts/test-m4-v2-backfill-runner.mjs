import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { MemoryCatalog } from '../src/fabric-store.mjs';
import { SqliteConversationArchive } from '../src/conversation-archive-v1.mjs';
import { ciphertextContentId, normalizeIngestKeyRing, normalizedObservationDigest } from '../src/ingest/raw-event-contract.mjs';
import { EncryptedOutbox } from '../src/ingest/outbox.mjs';
import { ConversationEventPlaintextOutbox } from '../src/ingest/conversation-event-v3-outbox.mjs';
import { aggregatePauseCheckpointInputs, createPauseManifest } from '../src/migration-pause.mjs';
import { createM4BackfillGateVerifier, createM4RollbackManifest } from '../src/migration/m4-backfill-gate.mjs';
import { createM4V2ArchiveSource } from '../src/migration/m4-v2-archive-source.mjs';
import { M4ProgressStore } from '../src/migration/m4-progress-store.mjs';
import { planM4V2Backfill, runM4V2Backfill } from '../src/migration/m4-v2-backfill-runner.mjs';
import { deriveEventIdV2, deriveLogicalMessageIds, deriveSessionIdV2, opaqueContextTag } from '../src/ingest/raw-projection-v2.mjs';
import { canonicalJson } from '../src/ingest/transcripts/canonical.mjs';

const KEY = Buffer.alloc(32, 7).toString('base64');
const LOGICAL = Buffer.alloc(32, 8).toString('base64');
const TAG_KEY = Buffer.alloc(32, 9).toString('base64');
const EVENT_KEY = Buffer.alloc(32, 5);
const INGEST_KEYS = { keys: { ingest: KEY }, digestKey: KEY,
  authorizations: { ingest: { actors: ['runner-actor'], sourceInstances: ['runner-source'] } },
  logicalMessageKeys: { currentKeyVersion: 'logical-k1', keys: { 'logical-k1': LOGICAL } } };
const DIGEST_KEY = normalizeIngestKeyRing(INGEST_KEYS).digestKey;
const OWNER = `catalog-k1:${'a'.repeat(64)}`;
const SOURCE = `catalog-k1:${'b'.repeat(64)}`;
const digest = value => `sha256:${value.repeat(64)}`;
const projectedEventId = eventId => `cevt_${crypto.createHash('sha256').update(canonicalJson(['amf.m4/v2-event-id/v1', eventId]), 'utf8').digest('hex')}`;

function tag(namespace, value) { return opaqueContextTag(namespace, value, TAG_KEY, 'routing-k1'); }
function keyDocument(id, byte) { return { schema: 'amf.migration-signing-key/v1', keyId: id, key: Buffer.alloc(32, byte).toString('base64') }; }
function gateInput() {
  const pauseKey = keyDocument('runner-pause-key', 10); const rollbackKey = keyDocument('runner-rollback-key', 11);
  const collector = `pause-collector-${'1'.repeat(64)}`;
  const sourceCheckpoint = { id: 'source-checkpoint-runner', digest: digest('5') };
  const input = { schema: 'amf.migration-pause-checkpoints/v1', manifestId: 'pause-manifest-runner', revision: 1, keyId: pauseKey.keyId,
    pause: { state: 'paused', collectorCursor: { id: 'collector-cursor-runner', digest: digest('1') }, pendingOutbox: { id: 'pending-outbox-runner', digest: digest('2') }, acknowledgements: { id: 'acknowledgements-runner', digest: digest('3') }, deadLetters: { id: 'dead-letters-runner', digest: digest('4') }, sourceCheckpoint, nativeTranscriptAuthority: { id: 'native-authority-runner', digest: digest('6') }, evidence: { id: collector, digest: digest('7') } } };
  const roster = { schema: 'amf.migration-pause-collector-roster/v1', manifestId: input.manifestId, revision: input.revision, keyId: pauseKey.keyId, collectors: [collector] };
  const pauseManifest = createPauseManifest(aggregatePauseCheckpointInputs([input], roster), pauseKey);
  const rollbackManifest = createM4RollbackManifest({ schema: 'amf.migration-manifest/v1', manifestId: 'rollback-manifest-runner', phase: 'rollback', revision: 1,
    rollback: { pauseEvidence: { manifestId: pauseManifest.manifestId, digest: pauseManifest.integrity.payloadDigest, signature: pauseManifest.integrity.signature }, sourceCheckpoint: pauseManifest.pause.sourceCheckpoint, targetCheckpoint: { id: 'target-checkpoint-runner', digest: digest('8') }, compatibilityRouteRevision: 'compatibility-route-runner', recoveryCopy: { id: 'recovery-copy-runner', digest: digest('9') }, restoreTest: 'passed' } }, rollbackKey);
  return { runId: 'm4-runner-001', phase: 'v2-archive', pauseManifest, pauseKeyDocument: pauseKey, rollbackManifest, rollbackKeyDocument: rollbackKey };
}

function item({ suffix, role = 'user', direction = role === 'assistant' ? 'outbound' : 'inbound' }) {
  const sender = tag('sender', 'runner-sender'); const conversation = tag('conversation', 'runner-conversation');
  const logical = { canonicalSenderIdentity: 'runner-sender', senderTag: sender, conversationTag: conversation, direction, nativePlatform: 'runner', nativeConversationId: 'runner-conversation', nativeMessageId: `runner-${suffix}` };
  const derived = deriveLogicalMessageIds(logical, INGEST_KEYS.logicalMessageKeys); const raw = Buffer.from(`synthetic-${suffix}`);
  const eventId = deriveEventIdV2({ sourceKind: 'codex', observationClass: 'native', rawBytes: raw }); const sessionId = deriveSessionIdV2({ sourceKind: 'codex', conversationTag: conversation });
  const normalized = { role, contentType: role === 'system' ? 'structured' : 'text', value: role === 'system' ? { ignored: true } : `visible ${suffix}` };
  const event = { schema: 'amf.raw-event/v2', eventId, sessionId, occurredAt: '2026-07-21T12:00:00Z', source: { runtime: 'codex', subtype: 'message' }, logical, normalized, raw: { encoding: 'base64', line: raw.toString('base64'), lineEnding: 'lf' } };
  const projection = { schema: 'amf.raw-event-projection/v2', eventId, sessionId, logicalMessageId: derived.logicalMessageId, logicalMessageAliases: derived.aliases, derivationVersion: 'amf-logical-message/v1', keyVersion: derived.keyVersion, sourceKind: 'codex', observationClass: 'native', direction, conversationKind: 'dm', contextTags: { actor: [tag('actor', 'runner-actor')], sender: [sender], conversation: [conversation] }, subtype: 'message', occurredAt: event.occurredAt, editedAt: null, nativeRevision: 1, sourceSequence: 1, authoritativeDeletion: false, role, contentType: normalized.contentType, contentParts: 1, hasContent: true, normalizationVersion: 'amf-observation-normalization/v1', normalizedPayloadDigest: normalizedObservationDigest({ event }, DIGEST_KEY) };
  return { event, projection };
}

function envelope(value) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-runner-envelope-'));
  try { return new EncryptedOutbox({ rootPath: root, encryptionKey: KEY, digestKey: KEY, sourceInstanceId: 'runner-source', actorId: 'runner-actor', keyId: 'ingest' }).encrypt(value); }
  finally { fs.rmSync(root, { recursive: true, force: true }); }
}

async function sourceFixture(startCheckpoint) {
  const catalog = new MemoryCatalog(); const envelopes = new Map();
  for (const value of [item({ suffix: 'user' }), item({ suffix: 'assistant', role: 'assistant' }), item({ suffix: 'system', role: 'system', direction: 'internal' })]) {
    const encrypted = envelope(value); const row = { eventId: value.event.eventId, sessionId: value.event.sessionId, logicalMessageId: value.projection.logicalMessageId, contentId: ciphertextContentId(encrypted), payloadDigest: encrypted.payloadDigest, projection: value.projection, ownerTag: OWNER, sourceTag: SOURCE, createdAt: '2026-07-21T12:00:01Z' };
    envelopes.set(row.contentId, encrypted);
    await catalog.ingestRawEventV2(row, { contentId: row.contentId, mediaType: 'application/json', byteLength: 1, storageRef: 'synthetic', createdAt: row.createdAt }, { id: `audit-${row.eventId.slice(4, 36)}`, ts: row.createdAt, actorTag: OWNER, action: 'synthetic', targetId: row.eventId, details: {} });
  }
  return createM4V2ArchiveSource({ catalog, rawStore: { async getClientCiphertext(id) { return structuredClone(envelopes.get(id)); } }, ingestKeys: INGEST_KEYS,
    verifyCatalogBinding: async () => ({ owner: true, source: true }), auditDecrypt: async input => ({ recorded: true, eventId: input.eventId, contentId: input.contentId }),
    integrityFor: async () => ({ keyId: 'runner-event-key', key: EVENT_KEY, sentAt: '2026-07-21T12:01:00Z', nonce: 'runnernonce000001' }), startCheckpoint, pageLimit: 2 });
}

function lease() { return { async acquire() {}, async heartbeat() {}, async release() {} }; }
function runtimeFactories(root, calls) {
  return {
    lease: async input => { calls.push(['lease', input]); return lease(); },
    source: async input => { calls.push(['source', input]); return sourceFixture(input.sourceCheckpoint); },
    outbox: async input => { calls.push(['outbox', input]); return new ConversationEventPlaintextOutbox({ rootPath: path.join(root, 'outbox'), resolveIntegrityKey: keyId => keyId === 'runner-event-key' ? EVENT_KEY : null, clock: () => Date.parse('2026-07-21T12:02:00Z'), nonceFactory: () => 'deliverynonce000001' }); },
    archive: async input => { calls.push(['archive', input]); return { archive: new SqliteConversationArchive({ filename: path.join(root, 'archive.sqlite'), resolveIntegrityKey: keyId => keyId === 'runner-event-key' ? EVENT_KEY : null, resolveExpiresAt: () => '2027-07-21T12:00:00Z', cursorKey: Buffer.alloc(32, 3) }), resolveIntegrityKey: keyId => keyId === 'runner-event-key' ? EVENT_KEY : null }; },
    checkpointStore: async input => { calls.push(['checkpointStore', input]); return new M4ProgressStore({ rootPath: path.join(root, 'progress'), runId: input.runId, phase: input.phase, planDigest: input.planDigest }); },
  };
}

test('planning is resource-free and running composes real v2 source through archive progress', async () => {
  const gate = gateInput(); const calls = []; const plan = await planM4V2Backfill({ gateInput: gate, maxEvents: 1 });
  assert.equal(calls.length, 0);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-m4-runner-'));
  try {
    const first = await runM4V2Backfill({ gateInput: gate, maxEvents: 1, confirmedPlanDigest: plan.planDigest, factories: runtimeFactories(root, calls) });
    assert.deepEqual(calls.map(call => call[0]), ['lease', 'source', 'outbox', 'archive', 'checkpointStore']);
    assert.deepEqual(Object.keys(first).sort(), ['complete', 'duplicates', 'lastCheckpoint', 'phase', 'processed', 'runId', 'schema']);
    assert.equal(first.processed, 1); assert.equal(first.complete, false);
    const secondCalls = []; const second = await runM4V2Backfill({ gateInput: gate, maxEvents: 1, confirmedPlanDigest: plan.planDigest, factories: runtimeFactories(root, secondCalls) });
    assert.equal(second.processed, 1); assert.equal(second.complete, true); assert.equal(second.duplicates, 0);
    const db = new SqliteConversationArchive({ filename: path.join(root, 'archive.sqlite'), resolveIntegrityKey: keyId => keyId === 'runner-event-key' ? EVENT_KEY : null, resolveExpiresAt: () => '2027-07-21T12:00:00Z', cursorKey: Buffer.alloc(32, 3) });
    const stored = db.db.prepare('SELECT event_id, event_json FROM conversation_archive_events_v1 ORDER BY event_id').all();
    const expected = [item({ suffix: 'user' }), item({ suffix: 'assistant', role: 'assistant' })]
      .map(value => projectedEventId(value.event.eventId)).sort();
    const systemId = projectedEventId(item({ suffix: 'system', role: 'system', direction: 'internal' }).event.eventId);
    assert.deepEqual(stored.map(row => row.event_id), expected);
    assert.deepEqual(stored.map(row => JSON.parse(row.event_json).role).sort(), ['assistant', 'user']);
    assert.equal(stored.some(row => row.event_id === systemId), false);
    db.close();
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('wrong confirmation invokes no factory and no resource write', async () => {
  const gate = gateInput(); const plan = await planM4V2Backfill({ gateInput: gate, maxEvents: 1 }); let calls = 0;
  await assert.rejects(() => runM4V2Backfill({ gateInput: gate, maxEvents: 1, confirmedPlanDigest: digest('f'), factories: { lease: async () => { calls += 1; }, source: async () => { calls += 1; }, outbox: async () => { calls += 1; }, archive: async () => { calls += 1; }, checkpointStore: async () => { calls += 1; } } }), { code: 'm4_runner_plan_confirmation_invalid' });
  assert.match(plan.planDigest, /^sha256:/); assert.equal(calls, 0);
});

test('factory failures close prior resources, and primary execution failures win over close failures', async () => {
  const gate = gateInput(); const plan = await planM4V2Backfill({ gateInput: gate, maxEvents: 1 }); const closed = [];
  const leaseResource = { async acquire() {}, async heartbeat() {}, async release() {}, async close() { closed.push('lease'); } };
  await assert.rejects(() => runM4V2Backfill({ gateInput: gate, maxEvents: 1, confirmedPlanDigest: plan.planDigest, factories: { lease: async () => leaseResource, source: async () => { throw new Error('private'); }, outbox: async () => ({}), archive: async () => ({}), checkpointStore: async () => ({}) } }), { code: 'm4_runner_source_factory_failed' });
  assert.deepEqual(closed, ['lease']);
  const resource = { async acquire() {}, async heartbeat() {}, async release() {}, async close() { throw new Error('close'); } };
  await assert.rejects(() => runM4V2Backfill({ gateInput: gate, maxEvents: 1, confirmedPlanDigest: plan.planDigest, factories: { lease: async () => resource, source: async () => ({ open() { throw new Error('open'); } }), outbox: async () => ({ enqueue() {}, deliver() {} }), archive: async () => ({ archive: { async append() {}, async tombstone() {} }, resolveIntegrityKey: () => EVENT_KEY }), checkpointStore: async () => ({ async load() { return null; }, async commit() {} }) } }), { code: 'm4_backfill_source_open_failed' });
});

test('invalid factory results stop construction and close only already-created resources', async () => {
  const gate = gateInput(); const plan = await planM4V2Backfill({ gateInput: gate, maxEvents: 1 }); const calls = [];
  const laterFactories = {
    lease: async () => ({}),
    source: async () => { calls.push('source'); return {}; },
    outbox: async () => { calls.push('outbox'); return {}; },
    archive: async () => { calls.push('archive'); return {}; },
    checkpointStore: async () => { calls.push('checkpointStore'); return {}; },
  };
  await assert.rejects(() => runM4V2Backfill({ gateInput: gate, maxEvents: 1, confirmedPlanDigest: plan.planDigest, factories: laterFactories }), { code: 'm4_runner_factory_result_invalid' });
  assert.deepEqual(calls, []);

  const closed = []; let checkpointStoreCalls = 0;
  const closeable = (name, resource) => ({ ...resource, async close() { closed.push(name); } });
  const invalidArchive = {
    lease: async () => closeable('lease', lease()),
    source: async () => closeable('source', { open() { return (async function* () {})(); } }),
    outbox: async () => closeable('outbox', { async enqueue() {}, async deliver() {} }),
    archive: async () => ({}),
    checkpointStore: async () => { checkpointStoreCalls += 1; return { async load() { return null; }, async commit() {} }; },
  };
  await assert.rejects(() => runM4V2Backfill({ gateInput: gate, maxEvents: 1, confirmedPlanDigest: plan.planDigest, factories: invalidArchive }), { code: 'm4_runner_factory_result_invalid' });
  assert.equal(checkpointStoreCalls, 0);
  assert.deepEqual(closed, ['outbox', 'source', 'lease']);
});

test('hostile factory and resource getters normalize to fixed validation errors', async () => {
  const gate = gateInput(); const plan = await planM4V2Backfill({ gateInput: gate, maxEvents: 1 }); let factoryCalls = 0;
  const hostileFactorySet = {
    source: async () => { factoryCalls += 1; return {}; },
    outbox: async () => { factoryCalls += 1; return {}; },
    archive: async () => { factoryCalls += 1; return {}; },
    checkpointStore: async () => { factoryCalls += 1; return {}; },
  };
  Object.defineProperty(hostileFactorySet, 'lease', { enumerable: true, get() { throw new Error('hostile factory getter'); } });
  await assert.rejects(() => runM4V2Backfill({ gateInput: gate, maxEvents: 1, confirmedPlanDigest: plan.planDigest, factories: hostileFactorySet }), { code: 'm4_runner_factories_invalid' });
  assert.equal(factoryCalls, 0);

  const closed = []; let laterCalls = 0;
  const hostileResource = {};
  Object.defineProperty(hostileResource, 'open', { get() { throw new Error('hostile resource getter'); } });
  await assert.rejects(() => runM4V2Backfill({ gateInput: gate, maxEvents: 1, confirmedPlanDigest: plan.planDigest, factories: {
    lease: async () => ({ async acquire() {}, async heartbeat() {}, async release() {}, async close() { closed.push('lease'); } }),
    source: async () => hostileResource,
    outbox: async () => { laterCalls += 1; return {}; },
    archive: async () => { laterCalls += 1; return {}; },
    checkpointStore: async () => { laterCalls += 1; return {}; },
  } }), { code: 'm4_runner_factory_result_invalid' });
  assert.equal(laterCalls, 0);
  assert.deepEqual(closed, ['lease']);
});

test('factory snapshot reads each factory property exactly once', async () => {
  const gate = gateInput(); const plan = await planM4V2Backfill({ gateInput: gate, maxEvents: 1 });
  const stable = {
    lease: async () => ({ async acquire() {}, async heartbeat() {}, async release() {} }),
    source: async () => ({ open() { return (async function* () {})(); } }),
    outbox: async () => ({ async enqueue() {}, async deliver() {} }),
    archive: async () => ({ archive: { async append() {}, async tombstone() {} }, resolveIntegrityKey: () => EVENT_KEY }),
    checkpointStore: async () => ({ async load() { return null; }, async commit() {} }),
  };
  const reads = new Map(); const factories = {};
  for (const [key, factory] of Object.entries(stable)) {
    Object.defineProperty(factories, key, { enumerable: true, get() {
      reads.set(key, (reads.get(key) || 0) + 1);
      return factory;
    } });
  }
  const result = await runM4V2Backfill({ gateInput: gate, maxEvents: 1, confirmedPlanDigest: plan.planDigest, factories });
  assert.equal(result.processed, 0);
  assert.deepEqual(Object.fromEntries(reads), { lease: 1, source: 1, outbox: 1, archive: 1, checkpointStore: 1 });
});

test('factory inputs are isolated and unknown factories, results, and cleanup-only failures are rejected', async () => {
  const gate = gateInput(); const plan = await planM4V2Backfill({ gateInput: gate, maxEvents: 1 }); const inputs = [];
  const emptySource = { open() { return (async function* () {})(); } };
  const stable = {
    lease: async input => { inputs.push(['lease', structuredClone(input)]); input.runId = 'mutated'; return { async acquire() {}, async heartbeat() {}, async release() {} }; },
    source: async input => { inputs.push(['source', structuredClone(input)]); return emptySource; },
    outbox: async () => ({ async enqueue() {}, async deliver() {} }),
    archive: async () => ({ archive: { async append() {}, async tombstone() {} }, resolveIntegrityKey: () => EVENT_KEY }),
    checkpointStore: async () => ({ async load() { return null; }, async commit() {} }),
  };
  const result = await runM4V2Backfill({ gateInput: gate, maxEvents: 1, confirmedPlanDigest: plan.planDigest, factories: stable });
  assert.equal(result.processed, 0);
  assert.equal(inputs[1][1].runId, plan.runId);
  let originalSourceCalls = 0; let replacementSourceCalls = 0;
  const snapshotted = {
    ...stable,
    lease: async () => {
      snapshotted.source = async () => { replacementSourceCalls += 1; return emptySource; };
      return { async acquire() {}, async heartbeat() {}, async release() {} };
    },
    source: async () => { originalSourceCalls += 1; return emptySource; },
  };
  await runM4V2Backfill({ gateInput: gate, maxEvents: 1, confirmedPlanDigest: plan.planDigest, factories: snapshotted });
  assert.equal(originalSourceCalls, 1);
  assert.equal(replacementSourceCalls, 0);
  await assert.rejects(() => runM4V2Backfill({ gateInput: gate, maxEvents: 1, confirmedPlanDigest: plan.planDigest, factories: { ...stable, extra: async () => {} } }), { code: 'm4_runner_factories_invalid' });
  await assert.rejects(() => runM4V2Backfill({ gateInput: gate, maxEvents: 1, confirmedPlanDigest: plan.planDigest, factories: { ...stable, archive: async () => ({ archive: { async append() {}, async tombstone() {} }, resolveIntegrityKey: () => EVENT_KEY, extra: true }) } }), { code: 'm4_runner_factory_result_invalid' });
  const cleanupFailure = { ...stable, lease: async () => {
    const resource = { async acquire() {}, async heartbeat() {}, async release() {} };
    Object.defineProperty(resource, 'close', { get() { throw new Error('hostile getter'); } });
    return resource;
  } };
  await assert.rejects(() => runM4V2Backfill({ gateInput: gate, maxEvents: 1, confirmedPlanDigest: plan.planDigest, factories: cleanupFailure }), { code: 'm4_runner_cleanup_failed' });
});

test('uncloneable plan and run gate inputs use fixed input errors', async () => {
  await assert.rejects(() => planM4V2Backfill({ gateInput: () => {}, maxEvents: 1 }), { code: 'm4_runner_plan_input_invalid' });
  await assert.rejects(() => runM4V2Backfill({ gateInput: () => {}, maxEvents: 1, confirmedPlanDigest: digest('a'), factories: {} }), { code: 'm4_runner_run_input_invalid' });
});

test('closeable resources close in reverse factory order after a successful empty batch', async () => {
  const gate = gateInput(); const plan = await planM4V2Backfill({ gateInput: gate, maxEvents: 1 }); const closed = [];
  const closable = name => ({ async close() { closed.push(name); } });
  const factories = {
    lease: async () => ({ ...closable('lease'), async acquire() {}, async heartbeat() {}, async release() {} }),
    source: async () => ({ ...closable('source'), open() { return (async function* () {})(); } }),
    outbox: async () => ({ ...closable('outbox'), async enqueue() {}, async deliver() {} }),
    archive: async () => ({ archive: { ...closable('archive'), async append() {}, async tombstone() {} }, resolveIntegrityKey: () => EVENT_KEY }),
    checkpointStore: async () => ({ ...closable('checkpointStore'), async load() { return null; }, async commit() {} }),
  };
  await runM4V2Backfill({ gateInput: gate, maxEvents: 1, confirmedPlanDigest: plan.planDigest, factories });
  assert.deepEqual(closed, ['checkpointStore', 'archive', 'outbox', 'source', 'lease']);
});
