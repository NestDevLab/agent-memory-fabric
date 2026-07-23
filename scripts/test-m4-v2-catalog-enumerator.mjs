import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { MemoryCatalog, PostgresCatalog, SqliteCatalog } from '../src/fabric-store.mjs';
import { opaqueContextTag } from '../src/ingest/raw-projection-v2.mjs';

const TAG_KEY = Buffer.alloc(32, 7).toString('base64');
const OWNER_TAG = `catalog-k1:${'a'.repeat(64)}`;
const SOURCE_TAG = `catalog-k1:${'b'.repeat(64)}`;
const CREATED_AT = '2026-07-21T12:00:00Z';

function tag(namespace, value) {
  return opaqueContextTag(namespace, value, TAG_KEY, 'routing-k1');
}

function id(prefix, character) {
  return `${prefix}_${character.repeat(64)}`;
}

function indexedId(prefix, index) {
  return `${prefix}_${index.toString(16).padStart(64, '0')}`;
}

function projection(eventId, sessionId, primaryLogicalId, aliases = [], { authoritativeDeletion = false } = {}) {
  return {
    schema: 'amf.raw-event-projection/v2',
    eventId,
    sessionId,
    logicalMessageId: primaryLogicalId,
    logicalMessageAliases: aliases,
    derivationVersion: 'amf-logical-message/v1',
    keyVersion: 'logical-k1',
    sourceKind: 'codex',
    observationClass: 'native',
    direction: 'inbound',
    conversationKind: 'dm',
    contextTags: {
      actor: [tag('actor', 'synthetic-actor')],
      sender: [tag('sender', 'synthetic-sender')],
      conversation: [tag('conversation', 'synthetic-conversation')],
      room: [tag('room', 'synthetic-room')],
    },
    subtype: authoritativeDeletion ? 'message.deleted' : 'message',
    occurredAt: '2026-07-21T12:00:00Z',
    editedAt: null,
    nativeRevision: 1,
    sourceSequence: 1,
    authoritativeDeletion,
    role: 'user',
    contentType: authoritativeDeletion ? 'none' : 'text',
    contentParts: authoritativeDeletion ? 0 : 1,
    hasContent: !authoritativeDeletion,
    normalizationVersion: 'amf-observation-normalization/v1',
    normalizedPayloadDigest: `hmac-sha256:normalized-k1:${eventId.slice(4)}`,
  };
}

function observation(eventCharacter, logicalCharacter, { primaryLogicalId = null, aliases = [], authoritativeDeletion = false } = {}) {
  const eventId = id('evt', eventCharacter);
  const sessionId = id('ses', '9');
  const logicalMessageId = id('lmsg', logicalCharacter);
  return {
    eventId,
    sessionId,
    logicalMessageId,
    contentId: eventCharacter.repeat(64),
    payloadDigest: `hmac-sha256:v1:${eventCharacter.repeat(64)}`,
    projection: projection(eventId, sessionId, primaryLogicalId || logicalMessageId, aliases, { authoritativeDeletion }),
    ownerTag: OWNER_TAG,
    sourceTag: SOURCE_TAG,
    createdAt: CREATED_AT,
  };
}

function logical(logicalMessageId, eventIds, { conflict = false, tombstoned = false } = {}) {
  return {
    logicalMessageId,
    preferredObservationId: eventIds[0],
    payloadConflict: conflict,
    tombstoned,
    selectionVersion: 'amf-observation-selection/v1',
    eventIds,
  };
}

function fixtureGroups() {
  const first = observation('1', '1');
  const second = observation('2', '2');
  const secondVariant = observation('5', '2');
  const secondDeletion = observation('6', '2', { authoritativeDeletion: true });
  const alias = { keyVersion: 'logical-k2', logicalMessageId: id('lmsg', '3') };
  const rotated = observation('3', '3', { primaryLogicalId: id('lmsg', '4'), aliases: [alias] });
  return [
    { logical: logical(first.logicalMessageId, [first.eventId]), observations: [first] },
    { logical: logical(second.logicalMessageId, [second.eventId, secondVariant.eventId, secondDeletion.eventId], { conflict: true, tombstoned: true }), observations: [second, secondVariant, secondDeletion] },
    { logical: logical(rotated.logicalMessageId, [rotated.eventId]), observations: [rotated] },
  ];
}

function rawRecord(row) {
  return {
    contentId: row.contentId,
    mediaType: 'application/json',
    byteLength: 1,
    storageRef: `synthetic/${row.contentId}`,
    createdAt: row.createdAt,
  };
}

function auditEvent(row) {
  return {
    id: `audit-${row.eventId.slice(4, 36)}`,
    ts: row.createdAt,
    actorTag: OWNER_TAG,
    action: 'synthetic',
    targetId: row.eventId,
    details: {},
  };
}

async function ingestGroups(catalog, groups) {
  for (const group of groups) {
    for (const row of group.observations) {
      await catalog.ingestRawEventV2(structuredClone(row), rawRecord(row), auditEvent(row));
    }
  }
}

async function ingestV1Only(catalog) {
  const eventId = id('evt', 'f');
  const sessionId = id('ses', 'f');
  const row = {
    eventId,
    sessionId,
    contentId: 'f'.repeat(64),
    payloadDigest: `hmac-sha256:v1:${'f'.repeat(64)}`,
    projection: {
      schema: 'amf.raw-event-projection/v1',
      eventId,
      sessionId,
      runtime: 'codex',
      subtype: 'unknown',
      occurredAt: CREATED_AT,
      role: 'user',
      contentType: 'text',
      contentParts: 1,
      hasContent: true,
    },
    ownerTag: OWNER_TAG,
    sourceTag: SOURCE_TAG,
    createdAt: CREATED_AT,
  };
  await catalog.ingestRawEvent(row, rawRecord(row), auditEvent(row));
}

async function exerciseShared(catalog) {
  const groups = fixtureGroups();
  await ingestGroups(catalog, groups);
  await ingestV1Only(catalog);

  const first = await catalog.listM4V2LogicalGroups({ limit: 2 });
  assert.equal(first.items.length, 2);
  assert.equal(first.next, groups[1].logical.logicalMessageId);
  assert.deepEqual(first.items.map(item => item.logical.logicalMessageId), groups.slice(0, 2).map(group => group.logical.logicalMessageId));
  assert.equal(first.items.flatMap(item => item.observations).some(item => item.eventId === id('evt', 'f')), false);
  assert.equal(first.items[1].logical.payloadConflict, true);
  assert.equal(first.items[1].logical.tombstoned, true);

  const final = await catalog.listM4V2LogicalGroups({ after: first.next, limit: 2 });
  assert.deepEqual(final.items.map(item => item.logical.logicalMessageId), [groups[2].logical.logicalMessageId]);
  assert.equal(final.next, null);
  assert.equal(final.items[0].observations[0].projection.logicalMessageId, id('lmsg', '4'));
  assert.equal(final.items[0].logical.logicalMessageId, id('lmsg', '3'));

  final.items[0].observations[0].projection.contextTags.actor[0] = 'mutated';
  const isolated = await catalog.listM4V2LogicalGroups({ after: first.next, limit: 2 });
  assert.notEqual(isolated.items[0].observations[0].projection.contextTags.actor[0], 'mutated');
  assert.deepEqual(await catalog.listM4V2LogicalGroups({ after: id('lmsg', 'f'), limit: 1 }), { items: [], next: null });
}

test('MemoryCatalog and SqliteCatalog share bounded stable v2 logical-group enumeration', async () => {
  await exerciseShared(new MemoryCatalog());
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-m4-catalog-'));
  const catalog = new SqliteCatalog({ databasePath: path.join(root, 'catalog.sqlite') });
  try {
    const indexes = catalog.db.prepare("PRAGMA index_list('raw_events_v2')").all();
    assert.equal(indexes.some(index => index.name === 'raw_events_v2_logical_message_idx'), true);
    await exerciseShared(catalog);
    const plan = catalog.db.prepare('EXPLAIN QUERY PLAN SELECT event_id FROM raw_events_v2 WHERE logical_message_id=? ORDER BY event_id ASC')
      .all(id('lmsg', '1')).map(row => row.detail).join('\n');
    assert.match(plan, /raw_events_v2_logical_message_idx/);
  }
  finally { catalog.db.close(); fs.rmSync(root, { recursive: true, force: true }); }
});

test('group corruption and request bounds fail closed before enumeration', async () => {
  const catalog = new MemoryCatalog();
  await ingestGroups(catalog, fixtureGroups());
  for (const request of [null, [], 1, { limit: 0 }, { limit: 101 }, { after: 'not-an-id' }, { unknown: true }]) {
    assert.throws(() => catalog.listM4V2LogicalGroups(request), error => error.message === 'm4_v2_catalog_request_invalid' && error.status === 400);
  }
  const group = [...catalog.logicalMessages.values()][0];
  group.eventIds.push(id('evt', 'e'));
  assert.throws(() => catalog.listM4V2LogicalGroups(), error => error.message === 'm4_v2_catalog_group_invalid' && error.status === 500);

  const missing = new MemoryCatalog();
  await ingestGroups(missing, fixtureGroups());
  missing.rawEventsV2.delete(id('evt', '1'));
  assert.throws(() => missing.listM4V2LogicalGroups(), /m4_v2_catalog_group_invalid/);

  const extra = new MemoryCatalog();
  await ingestGroups(extra, fixtureGroups());
  const extraRow = observation('e', '1');
  extra.rawEventsV2.set(extraRow.eventId, extraRow);
  assert.throws(() => extra.listM4V2LogicalGroups(), /m4_v2_catalog_group_invalid/);

  const duplicate = new MemoryCatalog();
  await ingestGroups(duplicate, fixtureGroups());
  duplicate.logicalMessages.get(id('lmsg', '1')).eventIds.push(id('evt', '1'));
  assert.throws(() => duplicate.listM4V2LogicalGroups(), /m4_v2_catalog_group_invalid/);

  const unrelated = new MemoryCatalog();
  await ingestGroups(unrelated, fixtureGroups());
  unrelated.rawEventsV2.get(id('evt', '1')).projection.logicalMessageId = id('lmsg', 'd');
  unrelated.rawEventsV2.get(id('evt', '1')).projection.logicalMessageAliases = [];
  assert.throws(() => unrelated.listM4V2LogicalGroups(), /m4_v2_catalog_group_invalid/);

  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-m4-catalog-corrupt-'));
  const sqlite = new SqliteCatalog({ databasePath: path.join(root, 'catalog.sqlite') });
  try {
    await ingestGroups(sqlite, fixtureGroups());
    sqlite.db.prepare('UPDATE logical_messages_v2 SET event_ids_json=? WHERE logical_message_id=?')
      .run('{bad json', id('lmsg', '1'));
    assert.throws(() => sqlite.listM4V2LogicalGroups(), error => error.message === 'm4_v2_catalog_group_invalid' && error.status === 500);
    sqlite.db.prepare('UPDATE logical_messages_v2 SET event_ids_json=?,payload_conflict=? WHERE logical_message_id=?')
      .run(JSON.stringify([id('evt', '1')]), 2, id('lmsg', '1'));
    assert.throws(() => sqlite.listM4V2LogicalGroups(), error => error.message === 'm4_v2_catalog_group_invalid' && error.status === 500);
  } finally {
    sqlite.db.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('PostgresCatalog uses one repeatable-read client transaction and normalizes failures', async () => {
  const groups = fixtureGroups();
  const queries = [];
  let released = 0;
  const client = {
    async query(request) {
      queries.push(request.text);
      if (request.text.includes('logical_messages_v2')) return { rows: groups.slice(0, 2).map(group => ({
        logical_message_id: group.logical.logicalMessageId,
        preferred_observation_id: group.logical.preferredObservationId,
        payload_conflict: group.logical.payloadConflict,
        tombstoned: group.logical.tombstoned,
        selection_version: group.logical.selectionVersion,
        event_ids: group.logical.eventIds,
      })) };
      if (request.text.includes('raw_events_v2')) return { rows: groups.slice(0, 2).flatMap(group => group.observations).map(row => ({
        event_id: row.eventId, session_id: row.sessionId, logical_message_id: row.logicalMessageId,
        content_id: row.contentId, payload_digest: row.payloadDigest, projection_json: row.projection,
        owner_tag: row.ownerTag, source_tag: row.sourceTag, created_at: row.createdAt,
      })) };
      return { rows: [] };
    },
    release() { released += 1; },
  };
  const pool = { connect: async () => client, on() {} };
  const catalog = new PostgresCatalog({ pool });
  catalog.ready = async () => {};
  const result = await catalog.listM4V2LogicalGroups({ limit: 2 });
  assert.deepEqual(result.items, groups.slice(0, 2));
  assert.equal(queries[0], 'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
  assert.equal(queries.includes('COMMIT'), true);
  assert.equal(released, 1);
  assert.equal(queries.some(sql => sql.includes('raw_events_v2')), true);
  assert.equal(queries.filter(sql => sql.includes('raw_events_v2')).length, 1);
  assert.equal(queries.some(sql => sql.includes('logical_messages_v2')), true);
  assert.equal(queries.some(sql => /raw_sessions_v1|searchSessions|session compatibility/i.test(sql)), false);
  const logicalQuery = queries.find(sql => sql.includes('logical_messages_v2'));
  assert.match(logicalQuery, /LIMIT \$2/);
  const rawRequest = queries.find(sql => sql.includes('raw_events_v2'));
  assert.match(rawRequest, /logical_message_id=ANY\(\$1::text\[\]\)/);

  const failedQueries = [];
  let rollbackFailureReleaseReason = null;
  const failed = new PostgresCatalog({ pool: { connect: async () => ({
    query: async request => {
      failedQueries.push(request.text);
      if (request.text.includes('logical_messages_v2')) throw new Error('synthetic backend detail');
      if (request.text === 'ROLLBACK') throw new Error('synthetic rollback detail');
      return { rows: [] };
    },
    release(reason) {
      rollbackFailureReleaseReason = reason;
      throw new Error('synthetic release detail');
    },
  }), on() {} } });
  failed.ready = async () => {};
  await assert.rejects(failed.listM4V2LogicalGroups(), error => error.message === 'm4_v2_catalog_enumeration_failed' && error.status === 500);
  assert.equal(failedQueries.includes('ROLLBACK'), true);
  assert.equal(rollbackFailureReleaseReason instanceof Error, true);

  let timeoutReleaseReason = null;
  const timeout = new PostgresCatalog({ pool: { connect: async () => ({
    query: async request => {
      if (request.text.includes('logical_messages_v2')) {
        const error = new Error('catalog_unavailable');
        error.code = 'catalog_postgres_query_timeout';
        throw error;
      }
      return { rows: [] };
    },
    release(reason) { timeoutReleaseReason = reason; },
  }), on() {} } });
  timeout.ready = async () => {};
  await assert.rejects(timeout.listM4V2LogicalGroups(), error => error.message === 'm4_v2_catalog_enumeration_failed' && error.status === 500);
  assert.equal(timeoutReleaseReason instanceof Error, true);

  let connects = 0;
  const noQuery = new PostgresCatalog({ pool: { connect: async () => { connects += 1; return client; }, on() {} } });
  noQuery.ready = async () => { throw new Error('must not be called'); };
  await assert.rejects(noQuery.listM4V2LogicalGroups(null), error => error.message === 'm4_v2_catalog_request_invalid' && error.status === 400);
  assert.equal(connects, 0);
});

test('PostgresCatalog reads a production-shaped 4114-observation group without an event-ID parameter list', async () => {
  const logicalMessageId = id('lmsg', 'a');
  const observations = Array.from({ length: 4_114 }, (_, index) => {
    const eventId = indexedId('evt', index + 1);
    const row = observation('1', 'a');
    row.eventId = eventId;
    row.contentId = (index + 1).toString(16).padStart(64, '0');
    row.payloadDigest = `hmac-sha256:v1:${(index + 1).toString(16).padStart(64, '0')}`;
    row.projection.eventId = eventId;
    row.projection.normalizedPayloadDigest = `hmac-sha256:normalized-k1:${(index + 1).toString(16).padStart(64, '0')}`;
    return row;
  });
  const requests = [];
  const client = {
    async query(request) {
      requests.push(request);
      if (request.text.includes('logical_messages_v2')) return { rows: [{
        logical_message_id: logicalMessageId,
        preferred_observation_id: observations[0].eventId,
        payload_conflict: false,
        tombstoned: false,
        selection_version: 'amf-observation-selection/v1',
        event_ids: observations.map(row => row.eventId),
      }] };
      if (request.text.includes('raw_events_v2')) return { rows: observations.map(row => ({
        event_id: row.eventId, session_id: row.sessionId, logical_message_id: row.logicalMessageId,
        content_id: row.contentId, payload_digest: row.payloadDigest, projection_json: row.projection,
        owner_tag: row.ownerTag, source_tag: row.sourceTag, created_at: row.createdAt,
      })) };
      return { rows: [] };
    },
    release() {},
  };
  const catalog = new PostgresCatalog({ pool: { connect: async () => client, on() {} } });
  catalog.ready = async () => {};
  const result = await catalog.listM4V2LogicalGroups({ limit: 1 });
  assert.equal(result.items[0].observations.length, 4_114);
  const rawRequest = requests.find(request => request.text.includes('raw_events_v2'));
  assert.deepEqual(rawRequest.values, [[logicalMessageId]]);
  assert.equal(rawRequest.text.includes('ANY('), true);
});
