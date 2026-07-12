import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { FabricStore, MemoryCatalog, MemoryRawStore, SqliteCatalog } from '../src/fabric-store.mjs';
import { normalizeIngestKeyRing, normalizedObservationDigest } from '../src/ingest/raw-event-contract.mjs';
import { EncryptedOutbox } from '../src/ingest/outbox.mjs';
import {
  OBSERVATION_NORMALIZATION_VERSION,
  deriveEventIdV2,
  deriveLogicalMessageIds,
  deriveSessionIdV2,
  opaqueContextTag,
  normalizeSessionContextBinding,
  selectLogicalMessage,
  sessionContextBinding,
  validateProjectionV2
} from '../src/ingest/raw-projection-v2.mjs';

const INGEST_KEY = Buffer.alloc(32, 7).toString('base64');
const LOGICAL_K1 = Buffer.alloc(32, 8).toString('base64');
const LOGICAL_K2 = Buffer.alloc(32, 9).toString('base64');
const TAG_KEY = Buffer.alloc(32, 6).toString('base64');
const LOGICAL_KEYS = { currentKeyVersion: 'k2', keys: { k1: LOGICAL_K1, k2: LOGICAL_K2 } };
const KEY_RING = {
  keys: { ingest: INGEST_KEY }, digestKey: INGEST_KEY,
  authorizations: { ingest: { actors: ['raw-owner', 'raw-system', 'raw-assistant'], sourceInstances: ['host', 'system-host', 'assistant-host'] } },
  logicalMessageKeys: LOGICAL_KEYS
};

function eventId(char) { return `evt_${char.repeat(64)}`; }
function sessionId(char = 'b') { return `ses_${char.repeat(64)}`; }
function tag(namespace, literal) { return opaqueContextTag(namespace, literal, TAG_KEY, 'routing-k1'); }
const NORMALIZED_DIGEST_KEY = normalizeIngestKeyRing(KEY_RING).digestKey;
function payloadDigest(value) { return `hmac-sha256:payload-k1:${crypto.createHash('sha256').update(value).digest('hex')}`; }

function item({ runtime = 'hermes', id = null, keyRing = LOGICAL_KEYS, observationClass = 'native', nativeRevision = 1, editedAt = null, sourceSequence = 1, authoritativeDeletion = false, normalized = 'same', delivery = false, actor = 'raw-owner', sender = 'person:alice', role = 'user', room = 'native-room', thread = null } = {}) {
  const senderTag = tag('sender', sender);
  const conversationTag = tag('conversation', 'room:private');
  const logicalInput = {
    canonicalSenderIdentity: sender, senderTag, conversationTag, direction: 'inbound',
    ...(delivery ? { deliveryCorrelationId: 'delivery-strong-id' } : { nativePlatform: 'discord', nativeConversationId: 'native-room', nativeMessageId: 'native-message' })
  };
  const derived = deriveLogicalMessageIds(logicalInput, keyRing);
  const rawBytes = Buffer.from(`SYNTHETIC_${runtime}_${normalized}_${nativeRevision}_${sourceSequence}_${observationClass}_${actor}_${sender}_${role}`);
  const derivedSessionId = deriveSessionIdV2({ sourceKind: runtime, conversationTag });
  const derivedEventId = id || deriveEventIdV2({ sourceKind: runtime, observationClass, rawBytes });
  const event = {
    schema: 'amf.raw-event/v2', eventId: derivedEventId, sessionId: derivedSessionId, occurredAt: '2026-07-12T00:00:00Z',
    source: { runtime, subtype: authoritativeDeletion ? 'message.deleted' : 'message' }, logical: logicalInput,
    normalized: { role, contentType: authoritativeDeletion ? 'none' : 'text', value: authoritativeDeletion ? null : normalized },
    raw: { encoding: 'base64', line: rawBytes.toString('base64'), lineEnding: 'lf' }
  };
  const projection = {
    schema: 'amf.raw-event-projection/v2', eventId: derivedEventId, sessionId: derivedSessionId,
    logicalMessageId: derived.logicalMessageId, logicalMessageAliases: derived.aliases,
    derivationVersion: 'amf-logical-message/v1', keyVersion: derived.keyVersion,
    sourceKind: runtime, observationClass, direction: 'inbound', conversationKind: 'dm',
    contextTags: { actor: [tag('actor', actor)], sender: [senderTag], conversation: [conversationTag], room: [tag('room', room)], ...(thread ? { thread: [tag('thread', thread)] } : {}) },
    subtype: authoritativeDeletion ? 'message.deleted' : 'message', occurredAt: '2026-07-12T00:00:00Z', editedAt,
    nativeRevision, sourceSequence, authoritativeDeletion, role, contentType: authoritativeDeletion ? 'none' : 'text',
    contentParts: authoritativeDeletion ? 0 : 1, hasContent: !authoritativeDeletion,
    normalizationVersion: OBSERVATION_NORMALIZATION_VERSION, normalizedPayloadDigest: normalizedObservationDigest({ event }, NORMALIZED_DIGEST_KEY)
  };
  return { projection, event };
}

function envelope(rawItem, actor = 'raw-owner', sourceInstanceId = 'host') {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-v2-outbox-'));
  try {
    const outbox = new EncryptedOutbox({ rootPath: root, encryptionKey: INGEST_KEY, digestKey: INGEST_KEY, sourceInstanceId, actorId: actor, keyId: 'ingest' });
    return outbox.encrypt(rawItem);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

test('projection v2 accepts every runtime and rejects literal context routing or extra fields', () => {
  for (const runtime of ['codex', 'claude', 'hermes', 'openclaw', 'principia']) assert.equal(validateProjectionV2(item({ runtime }).projection).sourceKind, runtime);
  assert.throws(() => validateProjectionV2({ ...item().projection, contextTags: { sender: ['Alice'], conversation: [tag('conversation', 'room')] } }), /raw_projection_invalid/);
  assert.throws(() => validateProjectionV2({ ...item().projection, nativeRoomId: 'literal-room' }), /raw_projection_invalid/);
  assert.throws(() => deriveLogicalMessageIds({ canonicalSenderIdentity: 'person:alice', senderTag: tag('sender', 'alice'), conversationTag: tag('conversation', 'room'), direction: 'inbound' }, LOGICAL_KEYS), /strong_identifier_required/);
});

test('session binding contains only conversation, room and thread invariants', () => {
  const projection = item({ actor: 'raw-assistant', sender: 'agent:vitae', role: 'assistant', thread: 'reply-thread' }).projection;
  assert.deepEqual(sessionContextBinding(projection.contextTags), {
    conversation: projection.contextTags.conversation,
    room: projection.contextTags.room,
    thread: projection.contextTags.thread
  });
  assert.equal(JSON.stringify(sessionContextBinding(projection.contextTags)).includes(projection.contextTags.sender[0]), false);
  assert.equal(JSON.stringify(sessionContextBinding(projection.contextTags)).includes(projection.contextTags.actor[0]), false);
  assert.throws(() => normalizeSessionContextBinding({ ...sessionContextBinding(projection.contextTags), actor: projection.contextTags.actor }), /raw_session_binding_invalid/);
});

test('published conformance fixture and Codex/OpenClaw identifiers match executable derivation', () => {
  const fixture = JSON.parse(fs.readFileSync(new URL('./fixtures/raw-projection-v2.conformance.json', import.meta.url), 'utf8'));
  assert.equal(validateProjectionV2(fixture), fixture);
  assert.match(deriveSessionIdV2({ sourceKind: 'codex', nativeSessionId: 'rollout-uuid' }), /^ses_[a-f0-9]{64}$/);
  assert.equal(deriveSessionIdV2({ sourceKind: 'openclaw', nativeSessionId: 'agent:vitae:session:42' }), deriveSessionIdV2({ sourceKind: 'openclaw', nativeSessionId: 'agent:vitae:session:42' }));
  assert.notEqual(deriveSessionIdV2({ sourceKind: 'codex', nativeSessionId: 'same' }), deriveSessionIdV2({ sourceKind: 'openclaw', nativeSessionId: 'same' }));
  assert.match(deriveEventIdV2({ sourceKind: 'openclaw', nativeSessionId: 'session', nativeEventId: 'message', observationClass: 'native' }), /^evt_[a-f0-9]{64}$/);
});

test('logical selection is deterministic, native wins handoff, conflicts block and tombstones win', () => {
  const handoff = item({ runtime: 'principia', id: eventId('c'), observationClass: 'delivery-handoff', delivery: true }).projection;
  const native = item({ runtime: 'hermes', id: eventId('d'), nativeRevision: 2 }).projection;
  handoff.logicalMessageId = native.logicalMessageId;
  const selected = selectLogicalMessage([{ eventId: handoff.eventId, projection: handoff }, { eventId: native.eventId, projection: native }]);
  assert.equal(selected.preferredObservationId, native.eventId);
  const divergent = { ...handoff, normalizedPayloadDigest: payloadDigest('different') };
  assert.equal(selectLogicalMessage([{ eventId: divergent.eventId, projection: divergent }, { eventId: native.eventId, projection: native }]).payloadConflict, true);
  const deletion = item({ runtime: 'hermes', id: eventId('e'), authoritativeDeletion: true, nativeRevision: 3 }).projection;
  deletion.logicalMessageId = native.logicalMessageId;
  assert.deepEqual(selectLogicalMessage([{ eventId: native.eventId, projection: native }, { eventId: deletion.eventId, projection: deletion }]), {
    logicalMessageId: native.logicalMessageId, preferredObservationId: deletion.eventId, payloadConflict: false, tombstoned: true, selectionVersion: 'amf-observation-selection/v1'
  });
});

test('Fabric v2 joins K1 backfill to K2 realtime, keeps v1 dual-read and fails readiness closed before cutover', async () => {
  const catalog = new MemoryCatalog();
  const store = new FabricStore({ rawStore: new MemoryRawStore({ encryptionKey: Buffer.alloc(32, 5).toString('base64') }), catalog, ingestKeyRing: KEY_RING, legacyV1Writes: false });
  const k1 = item({ keyRing: { currentKeyVersion: 'k1', keys: LOGICAL_KEYS.keys } });
  const k2 = item({ keyRing: LOGICAL_KEYS, nativeRevision: 2 });
  const first = await store.ingestRawEvent({ actor: 'raw-owner', sourceInstanceId: 'host', projection: k1.projection, envelope: envelope(k1) });
  const second = await store.ingestRawEvent({ actor: 'raw-owner', sourceInstanceId: 'host', projection: k2.projection, envelope: envelope(k2) });
  assert.equal(second.logicalMessageId, first.logicalMessageId);
  assert.equal(second.preferredObservationId, k2.projection.eventId);
  assert.equal(second.payloadConflict, false);
  await store.ready();
  assert.equal(store.status().rawProjectionV2Ready, false);
  assert.equal(store.status().rawProjectionV2ReadinessReason, 'production_postgres_required');

  const legacyProjection = { schema: 'amf.raw-event-projection/v1', eventId: eventId('3'), sessionId: sessionId('3'), runtime: 'claude', subtype: 'user', occurredAt: '2026-07-12T00:00:00Z', role: 'user', contentType: 'text', contentParts: 1, hasContent: true };
  await assert.rejects(store.ingestRawEvent({ actor: 'raw-owner', sourceInstanceId: 'host', projection: legacyProjection, envelope: {} }), /raw_projection_v1_writes_disabled|raw_envelope/);
  const migrationStore = new FabricStore({ rawStore: new MemoryRawStore({ encryptionKey: Buffer.alloc(32, 4).toString('base64') }), catalog: new MemoryCatalog(), ingestKeyRing: KEY_RING });
  await migrationStore.ready();
  assert.equal(migrationStore.status().rawProjectionV2Ready, false);
  assert.equal(migrationStore.status().rawProjectionV2ReadinessReason, 'legacy_v1_writes_enabled');
});

test('SQLite v2 persists opaque routing only and dual-reads the session catalog', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-v2-sqlite-'));
  const databasePath = path.join(root, 'catalog.sqlite');
  const catalog = new SqliteCatalog({ databasePath });
  const store = new FabricStore({ rawStore: new MemoryRawStore({ encryptionKey: Buffer.alloc(32, 3).toString('base64') }), catalog, ingestKeyRing: KEY_RING, legacyV1Writes: false });
  try {
    const rawItem = item({ runtime: 'openclaw' });
    const result = await store.ingestRawEvent({ actor: 'raw-owner', sourceInstanceId: 'host', projection: rawItem.projection, envelope: envelope(rawItem) });
    assert.equal(result.status, 'stored');
    const sessions = await store.createSessionReader().search({ actor: 'raw-owner', query: 'openclaw', limit: 10 });
    assert.equal(sessions.items.length, 1);
    await store.ready();
    assert.equal(store.status().rawProjectionV2Ready, false);
    assert.equal(store.status().rawProjectionV2ReadinessReason, 'production_postgres_required');
    const bytes = fs.readFileSync(databasePath);
    for (const literal of ['person:alice', 'room:private', 'native-room', 'native-message', 'SYNTHETIC_openclaw']) assert.equal(bytes.includes(Buffer.from(literal)), false);
  } finally {
    await store.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('SQLite schema migration backfills v6 session bindings without destroying compatibility metadata', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-session-migration-'));
  const databasePath = path.join(root, 'catalog.sqlite');
  let catalog = new SqliteCatalog({ databasePath });
  try {
    const store = new FabricStore({ rawStore: new MemoryRawStore({ encryptionKey: Buffer.alloc(32, 3).toString('base64') }), catalog, ingestKeyRing: KEY_RING, legacyV1Writes: false });
    const rawItem = item({ runtime: 'openclaw' });
    await store.ingestRawEvent({ actor: 'raw-owner', sourceInstanceId: 'host', projection: rawItem.projection, envelope: envelope(rawItem) });
    const legacyContext = catalog.db.prepare('SELECT context_tags_json FROM raw_sessions_v1 WHERE session_id=?').get(rawItem.projection.sessionId).context_tags_json;
    catalog.db.prepare('UPDATE raw_sessions_v1 SET session_binding_json=NULL WHERE session_id=?').run(rawItem.projection.sessionId);
    catalog.close();

    catalog = new SqliteCatalog({ databasePath });
    const row = catalog.db.prepare('SELECT context_tags_json,session_binding_json FROM raw_sessions_v1 WHERE session_id=?').get(rawItem.projection.sessionId);
    assert.equal(row.context_tags_json, legacyContext, 'rollback compatibility metadata is preserved');
    assert.deepEqual(JSON.parse(row.session_binding_json), sessionContextBinding(rawItem.projection.contextTags));
    assert.deepEqual(catalog.getSession(rawItem.projection.sessionId).contextTags, sessionContextBinding(rawItem.projection.contextTags));
  } finally {
    try { catalog.close(); } catch {}
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('exact v2 retry stays on the atomic v2 duplicate path while server-derived metadata is untrusted', async () => {
  const catalog = new MemoryCatalog();
  const store = new FabricStore({ rawStore: new MemoryRawStore({ encryptionKey: Buffer.alloc(32, 2).toString('base64') }), catalog, ingestKeyRing: KEY_RING, legacyV1Writes: false });
  const rawItem = item({ runtime: 'hermes' });
  const input = { actor: 'raw-owner', sourceInstanceId: 'host', projection: rawItem.projection, envelope: envelope(rawItem) };
  assert.equal((await store.ingestRawEvent(input)).status, 'stored');
  assert.equal((await store.ingestRawEvent(input)).status, 'duplicate');
  assert.equal(catalog.rawEvents.size, 0, 'v2 retries must never invoke the v1 writer');
  assert.equal(catalog.rawEventsV2.size, 1);
  assert.equal(catalog.auditEvents.filter(event => event.action === 'raw_event_ingest' && event.outcome === 'duplicate').length, 1);

  const badId = structuredClone(rawItem);
  badId.projection.eventId = eventId('f'); badId.event.eventId = eventId('f');
  await assert.rejects(store.ingestRawEvent({ ...input, projection: badId.projection, envelope: envelope(badId) }), /raw_event_derivation_invalid/);
  const badDigest = structuredClone(rawItem);
  badDigest.projection.normalizedPayloadDigest = `hmac-sha256:v1:${'0'.repeat(64)}`;
  await assert.rejects(store.ingestRawEvent({ ...input, projection: badDigest.projection, envelope: envelope(badDigest) }), /raw_observation_normalization_invalid/);
});

test('v2 sessions accept multi-role events and retries but reject room/thread rebinding', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-session-binding-'));
  const catalogs = [new MemoryCatalog(), new SqliteCatalog({ databasePath: path.join(root, 'catalog.sqlite') })];
  try {
    for (const catalog of catalogs) {
      const store = new FabricStore({ rawStore: new MemoryRawStore({ encryptionKey: Buffer.alloc(32, 2).toString('base64') }), catalog, ingestKeyRing: KEY_RING, legacyV1Writes: false });
      const observations = [
        { actor: 'raw-owner', sender: 'person:alice', role: 'user', source: 'host' },
        { actor: 'raw-system', sender: 'system:vitae', role: 'system', source: 'system-host' },
        { actor: 'raw-assistant', sender: 'agent:vitae', role: 'assistant', source: 'assistant-host' }
      ].map((entry, index) => ({ ...entry, item: item({ ...entry, nativeRevision: index + 1, sourceSequence: index + 1 }) }));
      for (const observation of observations) {
        const result = await store.ingestRawEvent({ actor: observation.actor, sourceInstanceId: observation.source, projection: observation.item.projection, envelope: envelope(observation.item, observation.actor, observation.source) });
        assert.equal(result.status, 'stored');
      }
      const retry = observations[2];
      assert.equal((await store.ingestRawEvent({ actor: retry.actor, sourceInstanceId: retry.source, projection: retry.item.projection, envelope: envelope(retry.item, retry.actor, retry.source) })).status, 'duplicate');
      const retryWithRoutingDrift = structuredClone(retry.item);
      retryWithRoutingDrift.projection.contextTags.room = [tag('room', 'retry-other-room')];
      await assert.rejects(store.ingestRawEvent({ actor: retry.actor, sourceInstanceId: retry.source, projection: retryWithRoutingDrift.projection, envelope: envelope(retryWithRoutingDrift, retry.actor, retry.source) }), /raw_session_binding_conflict/);
      const session = await catalog.getSession(observations[0].item.projection.sessionId);
      assert.equal(session.eventCount, 3);
      assert.deepEqual(session.contextTags, sessionContextBinding(observations[0].item.projection.contextTags));
      const events = await catalog.listSessionEvents(session.id);
      assert.equal(new Set(events.map(event => event.ownerTag)).size, 3, 'actor ownership remains event-scoped');
      assert.equal(new Set(events.map(event => event.sourceTag)).size, 3, 'source identity remains event-scoped');

      const changedRoom = item({ actor: 'raw-assistant', sender: 'agent:vitae', role: 'assistant', room: 'other-room', nativeRevision: 4, sourceSequence: 4 });
      await assert.rejects(store.ingestRawEvent({ actor: 'raw-assistant', sourceInstanceId: 'assistant-host', projection: changedRoom.projection, envelope: envelope(changedRoom, 'raw-assistant', 'assistant-host') }), /raw_session_binding_conflict/);

      const existingEvent = events[0];
      const conversationProjection = structuredClone(existingEvent.projection);
      conversationProjection.eventId = eventId('9');
      conversationProjection.contextTags.conversation = [tag('conversation', 'other-conversation')];
      const conversationRecord = { ...existingEvent, eventId: conversationProjection.eventId, contentId: '9'.repeat(64), projection: conversationProjection, createdAt: '2026-07-12T00:00:09Z' };
      await assert.rejects(async () => catalog.ingestRawEventV2(conversationRecord, { contentId: conversationRecord.contentId, mediaType: 'cipher', byteLength: 1, storageRef: 'binding-conflict', createdAt: conversationRecord.createdAt }, { id: `conversation-conflict-${catalog.constructor.name}`, ts: conversationRecord.createdAt, actorTag: conversationRecord.ownerTag, action: 'raw_event_ingest', targetId: conversationRecord.eventId, details: {} }), /raw_session_binding_conflict/);
      assert.equal(await catalog.getRawEvent(conversationRecord.eventId), null, 'binding conflicts must leave no partial event state');

      const threaded = item({ actor: 'raw-assistant', sender: 'agent:vitae', role: 'assistant', thread: 'thread-a', nativeRevision: 5, sourceSequence: 5 });
      const threadedStore = new FabricStore({ rawStore: new MemoryRawStore({ encryptionKey: Buffer.alloc(32, 3).toString('base64') }), catalog: new MemoryCatalog(), ingestKeyRing: KEY_RING, legacyV1Writes: false });
      await threadedStore.ingestRawEvent({ actor: 'raw-assistant', sourceInstanceId: 'assistant-host', projection: threaded.projection, envelope: envelope(threaded, 'raw-assistant', 'assistant-host') });
      const changedThread = item({ actor: 'raw-system', sender: 'system:vitae', role: 'system', thread: 'thread-b', nativeRevision: 6, sourceSequence: 6 });
      await assert.rejects(threadedStore.ingestRawEvent({ actor: 'raw-system', sourceInstanceId: 'system-host', projection: changedThread.projection, envelope: envelope(changedThread, 'raw-system', 'system-host') }), /raw_session_binding_conflict/);
    }
  } finally {
    catalogs[1].close();
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('durable decrypt-intent audit failure prevents v2 plaintext validation and storage', async () => {
  const catalog = new MemoryCatalog();
  catalog.appendAudit = () => { throw new Error('audit_sink_down'); };
  const store = new FabricStore({ rawStore: new MemoryRawStore({ encryptionKey: Buffer.alloc(32, 1).toString('base64') }), catalog, ingestKeyRing: KEY_RING, legacyV1Writes: false });
  const rawItem = item();
  await assert.rejects(store.ingestRawEvent({ actor: 'raw-owner', sourceInstanceId: 'host', projection: rawItem.projection, envelope: envelope(rawItem) }), /catalog_unavailable/);
  assert.equal(catalog.rawEventsV2.size, 0);
  assert.equal(catalog.rawObjects.size, 0);
});
