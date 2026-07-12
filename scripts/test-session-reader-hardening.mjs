import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { FabricStore, MemoryCatalog, MemoryRawStore, SqliteCatalog } from '../src/fabric-store.mjs';

const KEY = Buffer.alloc(32, 71).toString('base64');
const KEY_RING = { keys: { 'reader-v1': KEY }, digestKey: KEY,
  authorizations: { 'reader-v1': { actors: ['collector'], sourceInstances: ['source'] } },
  logicalMessageKeys: { currentKeyVersion: 'logical-v1', keys: { 'logical-v1': KEY } } };
const ROOM = `hmac-sha256:routing-v1:${'1'.repeat(64)}`;
const OTHER_ROOM = `hmac-sha256:routing-v1:${'2'.repeat(64)}`;
const CONTEXT = { conversation: [ROOM], room: [ROOM] };
const OTHER_CONTEXT = { conversation: [OTHER_ROOM], room: [OTHER_ROOM] };

function session(id, index, contextTags) {
  const occurredAt = new Date(Date.parse('2026-07-12T12:00:00Z') + (index * 1000)).toISOString();
  return { id, runtime: 'hermes', ownerTag: 'ignored', sourceTag: 'source', conversationKind: 'group',
    contextTags, firstOccurredAt: occurredAt, lastOccurredAt: occurredAt, eventCount: 1,
    createdAt: occurredAt };
}

function participantEvent(id, sessionId, ownerTag, occurredAt) {
  return { eventId: id, sessionId, logicalMessageId: `logical-${id}`, contentId: '0'.repeat(64),
    payloadDigest: '1'.repeat(64), ownerTag, sourceTag: 'source', createdAt: occurredAt,
    projection: { schema: 'amf.raw-event-projection/v2', eventId: id, sessionId,
      logicalMessageId: `logical-${id}`, occurredAt } };
}

test('session reader pages more than 64 context-filtered candidates with MAC-bound keyset cursors', async () => {
  const rawStore = new MemoryRawStore({ encryptionKey: KEY }); const catalog = new MemoryCatalog();
  const ownerTag = rawStore.opaqueTag('raw-owner', 'reader');
  for (let index = 0; index < 65; index += 1) {
    const item = session(`wrong-${String(index).padStart(3, '0')}`, 1000 + index, OTHER_CONTEXT);
    catalog.rawSessions.set(item.id, item);
    catalog.rawEventsV2.set(`wrong-event-${index}`, participantEvent(`wrong-event-${index}`, item.id,
      ownerTag, item.createdAt));
  }
  for (let index = 0; index < 71; index += 1) {
    const item = session(`right-${String(index).padStart(3, '0')}`, index, CONTEXT);
    catalog.rawSessions.set(item.id, item);
    catalog.rawEventsV2.set(`right-event-${index}`, participantEvent(`right-event-${index}`, item.id,
      ownerTag, item.createdAt));
  }
  const store = new FabricStore({ rawStore, catalog, ingestKeyRing: KEY_RING, legacyV1Writes: false });
  const reader = store.createSessionReader(); const ids = []; let cursor = null; let firstCursor;
  do {
    const page = await reader.search({ actor: 'reader', query: '', cursor, limit: 20,
      context: { contextTags: CONTEXT }, from: null, to: null });
    ids.push(...page.items.map(item => item.id)); cursor = page.nextCursor;
    firstCursor ||= cursor;
  } while (cursor);
  assert.equal(ids.length, 71); assert.equal(new Set(ids).size, 71);
  assert.equal(ids.every(id => id.startsWith('right-')), true);
  const tampered = `${firstCursor.slice(0, -1)}${firstCursor.endsWith('A') ? 'B' : 'A'}`;
  await assert.rejects(reader.search({ actor: 'reader', query: '', cursor: tampered, limit: 20,
    context: { contextTags: CONTEXT }, from: null, to: null }), /invalid_request/);
});

test('Memory and SQLite newest event windows use effective occurredAt DESC and event-id tiebreak', () => {
  const occurred = ['2026-07-12T12:00:00.000Z', '2026-07-12T12:00:02.000Z',
    '2026-07-12T12:00:02.000Z'];
  const expected = ['evt_c', 'evt_b', 'evt_a'];
  const memory = new MemoryCatalog();
  for (const [index, eventId] of ['evt_a', 'evt_b', 'evt_c'].entries()) {
    memory.rawEventsV2.set(eventId, participantEvent(eventId, 'session-order', 'owner', occurred[index]));
  }
  assert.deepEqual(memory.listSessionEventsPage({ id: 'session-order', newest: true, limit: 3 }).items
    .map(item => item.eventId), expected);

  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-session-order-'));
  const sqlite = new SqliteCatalog({ databasePath: path.join(root, 'catalog.sqlite') });
  try {
    sqlite.db.prepare('INSERT INTO raw_sessions_v1(session_id,runtime,owner_tag,source_tag,conversation_kind,session_binding_json,first_occurred_at,last_occurred_at,event_count,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)')
      .run('session-order', 'hermes', 'owner', 'source', 'group', JSON.stringify(CONTEXT),
        occurred[0], occurred[2], 3, '2026-07-12T13:00:00.000Z');
    for (const [index, eventId] of ['evt_a', 'evt_b', 'evt_c'].entries()) {
      const contentId = String(index + 1).repeat(64);
      sqlite.db.prepare('INSERT INTO raw_objects_v2(content_id,media_type,byte_length,storage_ref,created_at) VALUES (?,?,?,?,?)')
        .run(contentId, 'test', 1, `test:${eventId}`, new Date(Date.parse('2026-07-12T14:00:00Z') - index).toISOString());
      sqlite.db.prepare('INSERT INTO raw_events_v2(event_id,session_id,logical_message_id,content_id,payload_digest,projection_json,owner_tag,source_tag,created_at) VALUES (?,?,?,?,?,?,?,?,?)')
        .run(eventId, 'session-order', `logical-${eventId}`, contentId, 'f'.repeat(64),
          JSON.stringify({ schema: 'amf.raw-event-projection/v2', eventId, sessionId: 'session-order',
            logicalMessageId: `logical-${eventId}`, occurredAt: occurred[index] }), 'owner', 'source',
          new Date(Date.parse('2026-07-12T14:00:00Z') - index).toISOString());
    }
    assert.deepEqual(sqlite.listSessionEventsPage({ id: 'session-order', newest: true, limit: 3 }).items
      .map(item => item.eventId), expected);
  } finally { sqlite.close(); fs.rmSync(root, { recursive: true, force: true }); }
});

test('SQLite applies context, time and keyset predicates before candidate limit', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-session-keyset-'));
  const sqlite = new SqliteCatalog({ databasePath: path.join(root, 'catalog.sqlite') });
  try {
    const insertSession = sqlite.db.prepare('INSERT INTO raw_sessions_v1(session_id,runtime,owner_tag,source_tag,conversation_kind,session_binding_json,first_occurred_at,last_occurred_at,event_count,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)');
    const insertObject = sqlite.db.prepare('INSERT INTO raw_objects_v2(content_id,media_type,byte_length,storage_ref,created_at) VALUES (?,?,?,?,?)');
    const insertEvent = sqlite.db.prepare('INSERT INTO raw_events_v2(event_id,session_id,logical_message_id,content_id,payload_digest,projection_json,owner_tag,source_tag,created_at) VALUES (?,?,?,?,?,?,?,?,?)');
    for (let index = 0; index < 67; index += 1) {
      const correct = index >= 65; const id = `${correct ? 'right' : 'wrong'}-${index}`;
      const time = new Date(Date.parse('2026-07-12T12:00:00Z') + ((100 - index) * 1000)).toISOString();
      const contentId = index.toString(16).padStart(64, '0'); const eventId = `evt_${index}`;
      insertSession.run(id, 'hermes', 'owner', 'source', 'group', JSON.stringify(correct ? CONTEXT : OTHER_CONTEXT),
        time, time, 1, time);
      insertObject.run(contentId, 'test', 1, `test:${id}`, time);
      insertEvent.run(eventId, id, `logical-${index}`, contentId, 'f'.repeat(64),
        JSON.stringify({ schema: 'amf.raw-event-projection/v2', occurredAt: time }), 'owner', 'source', time);
    }
    const first = sqlite.searchSessions({ ownerTags: ['owner'], contextTags: CONTEXT, query: '', limit: 1 });
    assert.deepEqual(first.map(item => item.id), ['right-65']);
    const after = { id: first[0].id, createdAt: first[0].createdAt,
      lastOccurredAt: first[0].lastOccurredAt };
    const second = sqlite.searchSessions({ ownerTags: ['owner'], contextTags: CONTEXT, query: '', limit: 1,
      after });
    assert.deepEqual(second.map(item => item.id), ['right-66']);
  } finally { sqlite.close(); fs.rmSync(root, { recursive: true, force: true }); }
});
