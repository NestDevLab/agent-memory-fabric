import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  POSTGRES_SCHEMA,
  POSTGRES_SCHEMA_VERSION,
  FabricStore,
  MemoryRawStore,
  PostgresCatalog,
  createFabricStoreFromEnv,
  identityPairLockKey
} from '../src/fabric-store.mjs';

class FakePool {
  constructor({ failInitialization = false, schemaVersion = null, hangConnect = false, hangQuery = false } = {}) {
    this.failInitialization = failInitialization;
    this.schemaVersion = schemaVersion;
    this.hangConnect = hangConnect;
    this.hangQuery = hangQuery;
    this.queries = [];
    this.rawObjects = new Map();
    this.proposals = new Map();
    this.proposalsByKey = new Map();
    this.curatorReceipts = new Map();
    this.auditEvents = new Map();
    this.rawEvents = new Map();
    this.rawSessions = new Map();
    this.connectCalls = 0;
    this.releaseCalls = 0;
    this.endCalls = 0;
    this.loseNextCommitAck = false;
    this.failNextProposalInsert = false;
  }

  on() {}

  async connect() {
    this.connectCalls += 1;
    if (this.hangConnect) return new Promise(() => {});
    return {
      query: (query, values) => this.query(query, values),
      release: (error) => { this.releaseCalls += 1; this.releaseError = error || null; }
    };
  }

  async query(query, legacyValues = []) {
    const text = typeof query === 'string' ? query : query.text;
    const values = typeof query === 'string' ? legacyValues : (query.values || []);
    this.queries.push({ text, values });
    const compact = text.replace(/\s+/g, ' ').trim();
    if (this.hangQuery && compact.startsWith('SELECT max(version)')) return new Promise(() => {});
    if (this.failInitialization && compact.startsWith('CREATE SCHEMA')) throw new Error('postgres_unavailable');
    if (compact.startsWith('SELECT max(version) AS current_version')) return { rows: [{ current_version: this.schemaVersion }] };
    if (compact.startsWith('INSERT INTO agent_memory_fabric.raw_objects_v2')) {
      const [contentId, mediaType, byteLength, storageRef, createdAt] = values;
      if (!this.rawObjects.has(contentId)) this.rawObjects.set(contentId, { contentId, mediaType, byteLength, storageRef, createdAt });
      return { rows: [] };
    }
    if (compact.startsWith('SELECT * FROM agent_memory_fabric.raw_events_v1 WHERE event_id=$1')) return { rows: [this.rawEvents.get(values[0])].filter(Boolean) };
    if (compact.startsWith('INSERT INTO agent_memory_fabric.raw_sessions_v1')) {
      const [sessionId, runtime, ownerTag, sourceTag, occurredAt, createdAt] = values;
      if (!this.rawSessions.has(sessionId)) this.rawSessions.set(sessionId, { session_id: sessionId, runtime, owner_tag: ownerTag, source_tag: sourceTag, first_occurred_at: occurredAt, last_occurred_at: occurredAt, event_count: 0, created_at: createdAt });
      return { rows: [] };
    }
    if (compact.startsWith('INSERT INTO agent_memory_fabric.raw_events_v1')) {
      const [eventId, sessionId, contentId, payloadDigest, projectionJson, ownerTag, sourceTag, createdAt] = values;
      if (this.rawEvents.has(eventId)) return { rows: [] };
      const row = { event_id: eventId, session_id: sessionId, content_id: contentId, payload_digest: payloadDigest, projection_json: JSON.parse(projectionJson), owner_tag: ownerTag, source_tag: sourceTag, created_at: createdAt };
      this.rawEvents.set(eventId, row);
      return { rows: [row] };
    }
    if (compact.startsWith('UPDATE agent_memory_fabric.raw_sessions_v1 SET event_count=')) {
      const session = this.rawSessions.get(values[1]);
      if (session) {
        session.event_count += 1;
        if (values[0] && (!session.first_occurred_at || values[0] < session.first_occurred_at)) session.first_occurred_at = values[0];
        if (values[0] && (!session.last_occurred_at || values[0] > session.last_occurred_at)) session.last_occurred_at = values[0];
      }
      return { rows: [] };
    }
    if (compact.startsWith('SELECT s.* FROM agent_memory_fabric.raw_sessions_v1 s WHERE')) {
      const needle = String(values[1]).replaceAll('%', '').toLowerCase();
      const participantSessions = new Set([...this.rawEvents.values()].filter(row => values[0].includes(row.owner_tag)).map(row => row.session_id));
      const presented = values[4] ? JSON.parse(values[4]) : null;
      const routingKeys = new Set(['conversation', 'room', 'person', 'relationship', 'thread']);
      const after = values[5] ? { lastOccurredAt: values[5], createdAt: values[6], id: values[7] } : null;
      return { rows: [...this.rawSessions.values()].filter(row => participantSessions.has(row.session_id)
        && (!needle || `${row.session_id} ${row.runtime}`.toLowerCase().includes(needle))
        && (!values[2] || Date.parse(row.last_occurred_at || row.created_at) >= Date.parse(values[2]))
        && (!values[3] || Date.parse(row.first_occurred_at || row.created_at) <= Date.parse(values[3]))
        && (!presented || (() => {
          const binding = typeof row.session_binding_json === 'string'
            ? JSON.parse(row.session_binding_json) : row.session_binding_json;
          const entries = Object.entries(binding || {}).filter(([key]) => routingKeys.has(key));
          return entries.length > 0 && entries.every(([key, tags]) => Array.isArray(tags)
            && tags.some(tag => Array.isArray(presented[key]) && presented[key].includes(tag)));
        })())
        && (!after || Date.parse(row.last_occurred_at || row.created_at) < Date.parse(after.lastOccurredAt)
          || (Date.parse(row.last_occurred_at || row.created_at) === Date.parse(after.lastOccurredAt)
            && (row.created_at < after.createdAt || (row.created_at === after.createdAt && row.session_id > after.id)))))
        .sort((a, b) => Date.parse(b.last_occurred_at || b.created_at) - Date.parse(a.last_occurred_at || a.created_at)
          || b.created_at.localeCompare(a.created_at) || a.session_id.localeCompare(b.session_id))
        .slice(0, values[8]) };
    }
    if (compact.startsWith('SELECT * FROM agent_memory_fabric.raw_sessions_v1 WHERE session_id=$1')) return { rows: [this.rawSessions.get(values[0])].filter(Boolean) };
    if (compact.startsWith('SELECT EXISTS ( SELECT 1 FROM agent_memory_fabric.raw_events_v1')) {
      return { rows: [{ present: [...this.rawEvents.values()].some(row => row.session_id === values[0] && values[1].includes(row.owner_tag)) }] };
    }
    if (compact.startsWith('SELECT * FROM ( SELECT event_id,session_id,NULL::text AS logical_message_id')) {
      const newest = compact.includes('ORDER BY effective_at_ms DESC,event_id DESC');
      const rows = [...this.rawEvents.values()].filter(row => row.session_id === values[0]).sort((a, b) => newest
        ? Date.parse(b.projection_json.occurredAt || b.created_at) - Date.parse(a.projection_json.occurredAt || a.created_at)
          || b.event_id.localeCompare(a.event_id)
        : a.created_at.localeCompare(b.created_at) || a.event_id.localeCompare(b.event_id))
        .slice(values[4], values[4] + values[3]);
      return { rows };
    }
    if (compact.startsWith('SELECT * FROM agent_memory_fabric.raw_events_v1 WHERE session_id=$1')) return { rows: [...this.rawEvents.values()].filter(row => row.session_id === values[0]) };
    if (compact.startsWith('INSERT INTO agent_memory_fabric.fabric_proposals')) {
      if (this.failNextProposalInsert) {
        this.failNextProposalInsert = false;
        throw new Error('proposal_insert_failed');
      }
      const [id, ownerTag, scopeTag, status, contentId, idempotencyTag, sourceTag, createdAt] = values;
      const key = `${ownerTag}\u0000${idempotencyTag}`;
      if (this.proposalsByKey.has(key)) return { rows: [] };
      const row = {
        id, owner_tag: ownerTag, scope_tag: scopeTag, status, content_id: contentId,
        idempotency_tag: idempotencyTag, source_tag: sourceTag, created_at: createdAt
      };
      this.proposals.set(id, row);
      this.proposalsByKey.set(key, row);
      return { rows: [row] };
    }
    if (compact.startsWith('SELECT * FROM agent_memory_fabric.fabric_proposals WHERE owner_tag=$1')) {
      return { rows: [this.proposalsByKey.get(`${values[0]}\u0000${values[1]}`)].filter(Boolean) };
    }
    if (compact.includes('owner_tag = ANY($1::text[])')) {
      const found = [...this.proposals.values()].find((row) => values[0].includes(row.owner_tag) && values[1].includes(row.idempotency_tag));
      return { rows: [found].filter(Boolean) };
    }
    if (compact.startsWith('SELECT * FROM agent_memory_fabric.fabric_proposals WHERE id=$1')) {
      return { rows: [this.proposals.get(values[0])].filter(Boolean) };
    }
    if (compact.startsWith('SELECT * FROM agent_memory_fabric.curator_receipt_state_v1 WHERE proposal_id=$1')) {
      return { rows: [this.curatorReceipts.get(values[0])].filter(Boolean) };
    }
    if (compact.startsWith('SELECT r.* FROM agent_memory_fabric.curator_receipt_state_v1 r JOIN agent_memory_fabric.fabric_proposals p')) {
      const scoped = compact.includes('p.scope_tag = ANY($1::text[])');
      const scopeTags = scoped ? values[0] : null;
      const limit = scoped ? values[1] : values[0];
      const offset = scoped ? values[2] : values[1];
      const rows = [...this.curatorReceipts.values()]
        .filter(row => {
          const proposalRow = this.proposals.get(row.proposal_id);
          return proposalRow && (!scopeTags || scopeTags.includes(proposalRow.scope_tag));
        })
        .sort((left, right) => left.proposal_id.localeCompare(right.proposal_id))
        .slice(offset, offset + limit);
      return { rows };
    }
    if (compact.startsWith('INSERT INTO agent_memory_fabric.curator_receipt_state_v1')) {
      this.curatorReceipts.set(values[0], { proposal_id: values[0], status: values[1], decision_json: JSON.parse(values[2]), apply_json: null });
      return { rows: [] };
    }
    if (compact.startsWith('UPDATE agent_memory_fabric.curator_receipt_state_v1 SET status=$1,decision_json=$2::jsonb,apply_json=NULL')) {
      const row = this.curatorReceipts.get(values[2]);
      if (row) { row.status = values[0]; row.decision_json = JSON.parse(values[1]); row.apply_json = null; }
      return { rows: [] };
    }
    if (compact.startsWith('UPDATE agent_memory_fabric.fabric_proposals SET status=$1')) {
      const row = this.proposals.get(values[1]); if (row) row.status = values[0]; return { rows: [] };
    }
    if (compact.startsWith("UPDATE agent_memory_fabric.fabric_proposals SET status='promoted'")) {
      const row = this.proposals.get(values[0]); if (row) row.status = 'promoted'; return { rows: [] };
    }
    if (compact.startsWith('DELETE FROM agent_memory_fabric.raw_objects_v2')) {
      const referenced = [...this.proposals.values()].some((row) => row.content_id === values[0]);
      if (!referenced) this.rawObjects.delete(values[0]);
      return { rows: [] };
    }
    if (compact.startsWith('INSERT INTO agent_memory_fabric.audit_events_v2')) {
      this.auditEvents.set(values[0], values);
      return { rows: [] };
    }
    if (compact.startsWith('SELECT (SELECT count(*)::bigint')) {
      return { rows: [{ raw_objects: String(this.rawObjects.size), queued_proposals: String([...this.proposals.values()].filter((row) => row.status === 'queued').length), audit_events: String(this.auditEvents.size) }] };
    }
    if (compact === 'COMMIT' && this.loseNextCommitAck) {
      this.loseNextCommitAck = false;
      const error = new Error('connection lost after commit');
      error.code = 'ECONNRESET';
      throw error;
    }
    return { rows: [] };
  }

  async end() { this.endCalls += 1; }
}

function proposal(id, contentId, ownerTag = 'owner-secret', idempotencyTag = 'idem-secret') {
  return {
    id,
    ownerTag,
    scopeTag: 'scope-secret',
    status: 'queued',
    contentId,
    idempotencyTag,
    sourceTag: 'source-secret',
    createdAt: '2026-07-11T12:00:00.000Z'
  };
}

function raw(contentId) {
  return {
    contentId,
    mediaType: 'application/vnd.agent-memory-fabric.proposal+json',
    byteLength: 123,
    storageRef: `aa/${contentId}.enc.json`,
    createdAt: '2026-07-11T12:00:00.000Z'
  };
}

test('PostgreSQL catalog bootstraps the complete versioned metadata schema idempotently', async () => {
  const pool = new FakePool();
  const catalog = new PostgresCatalog({ pool });
  await Promise.all([catalog.ready(), catalog.ready()]);

  assert.equal(pool.connectCalls, 1);
  assert.equal(pool.releaseCalls, 1);
  const ddl = pool.queries.map((entry) => entry.text).join('\n');
  for (const table of ['schema_migrations', 'raw_objects_v2', 'fabric_proposals', 'identity_records', 'identity_records_v2', 'identity_events_v2', 'raw_retention_v2', 'retention_operations_v2', 'ingest_cursors', 'raw_sessions_v1', 'raw_events_v1', 'audit_events_v2', 'retention_tombstones', 'retention_tombstones_v2']) {
    assert.match(ddl, new RegExp(`${POSTGRES_SCHEMA}\\.${table}`));
  }
  assert.match(ddl, /UNIQUE\(owner_tag, idempotency_tag\)/);
  assert.match(ddl, /raw_sessions_v1[\s\S]*owner_tag TEXT NOT NULL[\s\S]*source_tag TEXT NOT NULL/);
  assert.equal(ddl.includes('owner_actor TEXT'), false);
  assert.equal(ddl.includes('source_instance_id TEXT'), false);
  assert.match(ddl, /value_ciphertext BYTEA/);
  assert.equal(ddl.includes('private proposal text'), false);
  const migration = pool.queries.find((entry) => entry.text.includes('schema_migrations(version) VALUES'));
  assert.deepEqual(migration.values, [POSTGRES_SCHEMA_VERSION]);
  assert.equal(catalog.status().healthy, true);
});

test('PostgreSQL proposal transaction resolves concurrent idempotency conflicts and parameterizes data', async () => {
  const pool = new FakePool();
  const catalog = new PostgresCatalog({ pool });
  const first = catalog.enqueueProposalWithRaw(proposal('proposal-1', 'a'.repeat(64)), raw('a'.repeat(64)));
  const second = catalog.enqueueProposalWithRaw(proposal('proposal-2', 'b'.repeat(64)), raw('b'.repeat(64)));
  const results = await Promise.all([first, second]);

  assert.equal(results.filter((result) => result.duplicate === false).length, 1);
  assert.equal(results.filter((result) => result.duplicate === true).length, 1);
  assert.equal(new Set(results.map((result) => result.record.id)).size, 1);
  assert.equal(pool.proposals.size, 1);
  assert.equal(pool.rawObjects.size, 1, 'duplicate transaction must remove unreferenced RAW metadata');

  const found = await catalog.findProposal(['owner-secret'], ['idem-secret']);
  assert.equal(found.id, results[0].record.id);
  assert.equal((await catalog.getProposal(found.id)).scopeTag, 'scope-secret');
  for (const { text, values } of pool.queries.filter((entry) => entry.values.length)) {
    for (const secret of ['owner-secret', 'idem-secret', 'scope-secret', 'source-secret']) {
      assert.equal(text.includes(secret), false, `SQL interpolated ${secret}`);
    }
    assert.ok(Array.isArray(values));
  }

  await catalog.appendAudit({
    id: 'audit-1', ts: '2026-07-11T12:01:00.000Z', actorTag: 'actor-secret', action: 'memory_propose', outcome: 'queued',
    requestId: 'request-1', targetId: found.id, scopeTag: 'scope-secret', details: { contentId: 'a'.repeat(64) }
  });
  const health = await catalog.health();
  assert.deepEqual({ rawObjects: health.rawObjects, queuedProposals: health.queuedProposals, auditEvents: health.auditEvents }, { rawObjects: 1, queuedProposals: 1, auditEvents: 1 });
  await catalog.close();
  await catalog.close();
  assert.equal(pool.endCalls, 1);
});

test('PostgreSQL receipt transaction preserves rejected/revoked terminal state and permits only identical replay', async () => {
  const pool = new FakePool(); const catalog = new PostgresCatalog({ pool });
  const queued = proposal('proposal-terminal-pg', 'c'.repeat(64));
  await catalog.enqueueProposalWithRaw(queued, raw('c'.repeat(64)));
  const receipt = {
    kind: 'decision', proposalId: queued.id, proposalScope: 'shared:global', decisionId: 'decision-terminal-pg', status: 'rejected',
    decisionDigest: '1'.repeat(64), proposalDigest: '2'.repeat(64), policyDigest: '3'.repeat(64), timestamp: '2026-07-12T12:00:00Z'
  };
  const audit = suffix => ({ id: `audit-terminal-${suffix}`, ts: '2026-07-12T12:00:00Z', actorTag: 'actor-tag', action: 'curation_decision_receipt', requestId: suffix, targetId: queued.id, details: {} });
  pool.proposals.get(queued.id).status = 'revoked';
  await assert.rejects(catalog.recordCuratorReceipt({ ...receipt, status: 'review_required' }, audit('late')), /receipt_transition_invalid/);
  assert.equal(pool.proposals.get(queued.id).status, 'revoked');
  pool.proposals.get(queued.id).status = 'queued';
  assert.equal((await catalog.recordCuratorReceipt(receipt, audit('first'))).status, 'rejected');
  pool.proposals.get(queued.id).status = 'revoked';
  assert.equal((await catalog.recordCuratorReceipt(receipt, audit('replay'))).duplicate, true);
  assert.equal(pool.proposals.get(queued.id).status, 'revoked');

  const other = proposal('proposal-terminal-pg-other', 'd'.repeat(64), 'owner-other', 'idem-other');
  other.scopeTag = 'scope-other';
  await catalog.enqueueProposalWithRaw(other, raw('d'.repeat(64)));
  const otherReceipt = { ...receipt, proposalId: other.id, decisionId: 'decision-other' };
  await catalog.recordCuratorReceipt(otherReceipt, audit('other'));
  assert.deepEqual((await catalog.listCuratorReceipts({ scopeTags: ['scope-secret'], offset: 0, limit: 1 })).map(row => row.proposalId), [queued.id]);
  assert.deepEqual((await catalog.listCuratorReceipts({ scopeTags: ['scope-other'], offset: 0, limit: 1 })).map(row => row.proposalId), [other.id]);
  assert.equal((await catalog.listCuratorReceipts({ scopeTags: null, offset: 0, limit: 1 })).length, 1, 'allow_all remains bounded');
});

test('PostgreSQL raw event/session catalog matches SQLite idempotency and safe projection contract', async () => {
  const pool = new FakePool();
  const catalog = new PostgresCatalog({ pool });
  const projection = { schema: 'amf.raw-event-projection/v1', eventId: `evt_${'a'.repeat(64)}`, sessionId: `ses_${'b'.repeat(64)}`, runtime: 'claude', subtype: 'user', occurredAt: '2026-07-12T00:00:00Z', role: 'user', contentType: 'text', contentParts: 1, hasContent: true };
  const record = { eventId: projection.eventId, sessionId: projection.sessionId, contentId: 'c'.repeat(64), payloadDigest: 'd'.repeat(64), projection, ownerTag: 'owner-tag', sourceTag: 'source-tag', createdAt: '2026-07-12T00:00:01Z' };
  const rawRecord = { contentId: record.contentId, mediaType: 'application/vnd.agent-memory-fabric.raw-event-ciphertext+json', byteLength: 456, storageRef: 'client-events/c.enc.json', createdAt: record.createdAt };
  const audit = { id: 'raw-audit-1', ts: record.createdAt, actorTag: 'actor-tag', action: 'raw_event_ingest', outcome: 'stored', requestId: 'request', targetId: record.eventId, details: {} };
  const first = await catalog.ingestRawEvent(record, rawRecord, audit);
  const duplicate = await catalog.ingestRawEvent(record, rawRecord, { ...audit, id: 'raw-audit-2' });
  assert.equal(first.duplicate, false);
  assert.equal(duplicate.duplicate, true);
  assert.equal((await catalog.searchSessions({ ownerTags: ['owner-tag'], query: 'claude', limit: 10 })).length, 1);
  assert.equal((await catalog.searchSessions({ ownerTags: ['owner-tag'], query: '%_', limit: 10 })).length, 0);
  assert.equal(await catalog.hasSessionParticipant(record.sessionId, ['owner-tag']), true);
  assert.equal(await catalog.hasSessionParticipant(record.sessionId, ['outsider-tag']), false);
  assert.deepEqual(await catalog.listSessionEventsPage({ id: record.sessionId, offset: 0, limit: 1 }).then(page => ({ count: page.items.length, hasMore: page.hasMore })), { count: 1, hasMore: false });
  const searchQuery = pool.queries.filter(entry => entry.text.includes('raw_sessions_v1') && entry.text.includes('ILIKE')).at(-1);
  assert.match(searchQuery.text, /ESCAPE '\\'/);
  assert.match(searchQuery.text, /ORDER BY coalesce\(s\.last_occurred_at,s\.created_at\) DESC,s\.created_at DESC,s\.session_id ASC/);
  assert.equal(searchQuery.values[1], '%\\%\\_%');
  assert.equal((await catalog.getSession(record.sessionId)).eventCount, 1);
  assert.equal((await catalog.listSessionEvents(record.sessionId))[0].projection.role, 'user');
  const hijackProjection = { ...projection, eventId: `evt_${'e'.repeat(64)}` };
  await assert.rejects(catalog.ingestRawEvent({ ...record, eventId: hijackProjection.eventId, projection: hijackProjection, ownerTag: 'other-owner-tag', contentId: 'f'.repeat(64) }, { ...rawRecord, contentId: 'f'.repeat(64) }, { ...audit, id: 'raw-audit-3' }), /raw_session_binding_conflict/);
  for (const query of pool.queries.filter(entry => entry.text.includes('raw_events_v1') && entry.values.length)) {
    assert.equal(query.text.includes('SYNTHETIC_PRIVATE'), false);
    assert.ok(Array.isArray(query.values));
  }
  await catalog.close();
});

test('PostgreSQL session queries bind context, time and keyset before limit and order newest by effective time', async () => {
  const pool = new FakePool(); const catalog = new PostgresCatalog({ pool });
  await catalog.ready();
  const room = `hmac-sha256:routing-v1:${'a'.repeat(64)}`;
  const contextTags = { conversation: [room], room: [room] };
  pool.rawSessions.set('session-1', { session_id: 'session-1', runtime: 'hermes', owner_tag: 'owner',
    source_tag: 'source', conversation_kind: 'group', session_binding_json: contextTags,
    first_occurred_at: '2026-07-12T12:00:00.000Z', last_occurred_at: '2026-07-12T12:00:02.000Z',
    event_count: 3, created_at: '2026-07-12T12:00:00.000Z' });
  for (const [index, eventId] of ['evt_a', 'evt_b', 'evt_c'].entries()) {
    const occurredAt = index === 0 ? '2026-07-12T12:00:00.000Z' : '2026-07-12T12:00:02.000Z';
    pool.rawEvents.set(eventId, { event_id: eventId, session_id: 'session-1', logical_message_id: `logical-${eventId}`,
      content_id: String(index + 1).repeat(64), payload_digest: 'f'.repeat(64), projection_json: { occurredAt },
      owner_tag: 'owner', source_tag: 'source', created_at: new Date(Date.parse('2026-07-12T13:00:00Z') - index).toISOString() });
  }
  const after = { lastOccurredAt: '2026-07-12T12:00:03.000Z',
    createdAt: '2026-07-12T12:00:03.000Z', id: 'prior' };
  await catalog.searchSessions({ ownerTags: ['owner'], query: '', limit: 10, contextTags,
    from: '2026-07-12T11:00:00.000Z', to: '2026-07-12T13:00:00.000Z', after });
  const query = pool.queries.findLast(entry => entry.text.includes('jsonb_each(s.session_binding_json)'));
  assert.ok(query.text.indexOf('jsonb_each') < query.text.indexOf('LIMIT $9'));
  assert.ok(query.text.indexOf('AND EXISTS (SELECT 1 FROM jsonb_each')
    < query.text.indexOf('AND NOT EXISTS (', query.text.indexOf('AND EXISTS (SELECT 1 FROM jsonb_each')));
  assert.match(query.text, /s\.session_id>\$8/);
  assert.deepEqual(query.values.slice(2, 9), ['2026-07-12T11:00:00.000Z',
    '2026-07-12T13:00:00.000Z', JSON.stringify(contextTags), after.lastOccurredAt,
    after.createdAt, after.id, 10]);
  assert.deepEqual((await catalog.listSessionEventsPage({ id: 'session-1', newest: true, limit: 3 })).items
    .map(item => item.eventId), ['evt_c', 'evt_b', 'evt_a']);
  const newestQuery = pool.queries.findLast(entry => entry.text.includes('effective_at_ms DESC'));
  assert.match(newestQuery.text, /ORDER BY effective_at_ms DESC,event_id DESC/);
  for (let index = 0; index < 65; index += 1) {
    const id = `contextless-${String(index).padStart(2, '0')}`;
    const occurredAt = new Date(Date.parse('2026-07-12T13:00:00.000Z') + index).toISOString();
    pool.rawSessions.set(id, { session_id: id, runtime: 'hermes', owner_tag: 'owner', source_tag: 'source',
      conversation_kind: 'group', session_binding_json: null, first_occurred_at: occurredAt,
      last_occurred_at: occurredAt, event_count: 1, created_at: occurredAt });
    pool.rawEvents.set(`contextless-event-${index}`, { event_id: `contextless-event-${index}`, session_id: id,
      content_id: 'a'.repeat(64), payload_digest: 'b'.repeat(64), projection_json: { occurredAt },
      owner_tag: 'owner', source_tag: 'source', created_at: occurredAt });
  }
  const prelimit = await catalog.searchSessions({ ownerTags: ['owner'], query: '', limit: 1, contextTags });
  assert.deepEqual(prelimit.map(item => item.id), ['session-1'],
    'contextless rows must be rejected before LIMIT so a valid older route remains visible');
  await catalog.close();
});

test('PostgreSQL raw ingest reconciles a lost COMMIT acknowledgement and retry stays idempotent', async () => {
  const pool = new FakePool();
  const catalog = new PostgresCatalog({ pool });
  const projection = { schema: 'amf.raw-event-projection/v1', eventId: `evt_${'9'.repeat(64)}`, sessionId: `ses_${'8'.repeat(64)}`, runtime: 'claude', subtype: 'user', occurredAt: '2026-07-12T01:00:00Z', role: 'user', contentType: 'text', contentParts: 1, hasContent: true };
  const record = { eventId: projection.eventId, sessionId: projection.sessionId, contentId: '7'.repeat(64), payloadDigest: `hmac-sha256:v1:${'6'.repeat(64)}`, projection, ownerTag: 'opaque-owner-tag', sourceTag: 'opaque-source-tag', createdAt: '2026-07-12T01:00:01Z' };
  const rawRecord = { contentId: record.contentId, mediaType: 'cipher', byteLength: 100, storageRef: 'client-events/7.enc.json', createdAt: record.createdAt };
  await catalog.ready();
  pool.loseNextCommitAck = true;
  const first = await catalog.ingestRawEvent(record, rawRecord, { id: 'raw-ambiguous-1', ts: record.createdAt, actorTag: 'audit-tag', action: 'raw_event_ingest', outcome: 'stored', targetId: record.eventId, details: {} });
  assert.equal(first.duplicate, false);
  assert.ok(pool.releaseError instanceof Error, 'ambiguous COMMIT client must be discarded');
  assert.equal(pool.rawEvents.size, 1);
  assert.equal(pool.rawSessions.get(record.sessionId).event_count, 1);
  const retry = await catalog.ingestRawEvent(record, rawRecord, { id: 'raw-ambiguous-2', ts: record.createdAt, actorTag: 'audit-tag', action: 'raw_event_ingest', outcome: 'duplicate', targetId: record.eventId, details: {} });
  assert.equal(retry.duplicate, true);
  assert.equal(pool.rawEvents.size, 1);
  assert.equal(pool.rawSessions.get(record.sessionId).event_count, 1);
  await catalog.close();
});

test('PostgreSQL catalog configuration is explicit and never falls back to SQLite', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-postgres-config-'));
  const base = { AMF_RAW_ENCRYPTION_KEY: 'a'.repeat(64), AMF_CATALOG_KIND: 'postgres' };
  try {
    assert.throws(() => createFabricStoreFromEnv({ rootPath: root, env: base }), /catalog_postgres_url_required/);
    assert.throws(() => createFabricStoreFromEnv({ rootPath: root, env: { ...base, AMF_CATALOG_DATABASE_URL: 'postgres://db/test', AMF_CATALOG_SSL_MODE: 'invalid' } }), /catalog_postgres_ssl_mode_invalid/);
    assert.throws(() => createFabricStoreFromEnv({ rootPath: root, env: { ...base, AMF_CATALOG_DATABASE_URL: 'postgres://db/test', AMF_CATALOG_POOL_MAX: '0' } }), /catalog_postgres_pool_max_invalid/);
    assert.throws(() => createFabricStoreFromEnv({ rootPath: root, env: { ...base, AMF_CATALOG_DATABASE_URL: 'postgres://db/test', AMF_CATALOG_CONNECT_TIMEOUT_MS: '0' } }), /invalid_environment:AMF_CATALOG_CONNECT_TIMEOUT_MS/);
    assert.throws(() => createFabricStoreFromEnv({ rootPath: root, env: { ...base, AMF_CATALOG_DATABASE_URL: 'postgres://db/test', AMF_CATALOG_QUERY_TIMEOUT_MS: 'forever' } }), /invalid_environment:AMF_CATALOG_QUERY_TIMEOUT_MS/);
    assert.throws(() => createFabricStoreFromEnv({ rootPath: root, env: { ...base, AMF_CATALOG_DATABASE_URL: 'postgres://db/test', AMF_CATALOG_STATEMENT_TIMEOUT_MS: '120001' } }), /invalid_environment:AMF_CATALOG_STATEMENT_TIMEOUT_MS/);
    assert.throws(() => createFabricStoreFromEnv({ rootPath: root, env: { ...base, AMF_CATALOG_KIND: 'unknown' } }), /catalog_kind_invalid/);
    assert.throws(() => createFabricStoreFromEnv({ rootPath: root, env: { ...base, AMF_CATALOG_DATABASE_URL: 'postgres://db/test', AMF_INGEST_KEY_RING_PATH: path.join(root, 'missing.json') } }), /raw_ingest_key_ring_file_invalid/);

    const ingestKeyRingPath = path.join(root, 'ingest-key-ring.json');
    fs.writeFileSync(ingestKeyRingPath, JSON.stringify({
      keys: { 'client-v1': crypto.randomBytes(32).toString('base64') },
      digestKey: crypto.randomBytes(32).toString('base64'),
      authorizations: { 'client-v1': { actors: ['synthetic-actor'], sourceInstances: ['synthetic-host'] } }
    }), { mode: 0o600 });

    let poolConfig;
    const pool = new FakePool();
    const store = createFabricStoreFromEnv({
      rootPath: root,
      env: {
        ...base, AMF_CATALOG_DATABASE_URL: 'postgres://db/amf_test', AMF_CATALOG_SSL_MODE: 'require', AMF_CATALOG_POOL_MAX: '7',
        AMF_CATALOG_CONNECT_TIMEOUT_MS: '4000', AMF_CATALOG_QUERY_TIMEOUT_MS: '9000', AMF_CATALOG_STATEMENT_TIMEOUT_MS: '8000',
        AMF_INGEST_KEY_RING_PATH: ingestKeyRingPath, AMF_INGEST_KEY_RING_JSON: '{invalid-json'
      },
      postgresPoolFactory: (config) => { poolConfig = config; return pool; }
    });
    assert.equal(store.status().backend, 'postgres');
    assert.equal(store.status().rawIngestConfigured, true, 'mounted key-ring path must take precedence over JSON compatibility input');
    assert.deepEqual(poolConfig, {
      connectionString: 'postgres://db/amf_test', ssl: { rejectUnauthorized: false }, max: 7,
      connectionTimeoutMillis: 4000, query_timeout: 9000, statement_timeout: 8000
    });
    await store.ready();
    await store.close();
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('PostgreSQL initialization failure is retained as unhealthy and does not switch adapters', async () => {
  const pool = new FakePool({ failInitialization: true });
  const catalog = new PostgresCatalog({ pool });
  await assert.rejects(catalog.ready(), /catalog_unavailable/);
  assert.equal(catalog.status().backend, 'postgres');
  assert.equal(catalog.status().healthy, false);
  assert.equal(catalog.status().lastError, 'catalog_postgres_operation_failed');
  assert.ok(pool.queries.some((entry) => entry.text === 'ROLLBACK'));
  await catalog.close();
});

test('PostgreSQL catalog bounds pool exhaustion and query stalls', async () => {
  const exhausted = new FakePool({ hangConnect: true });
  const connectCatalog = new PostgresCatalog({ pool: exhausted, connectTimeoutMs: 100, queryTimeoutMs: 200, statementTimeoutMs: 150 });
  const connectStarted = Date.now();
  await assert.rejects(connectCatalog.ready(), (error) => error.message === 'catalog_unavailable' && error.code === 'catalog_postgres_connect_timeout');
  assert.ok(Date.now() - connectStarted < 1000);
  await connectCatalog.close();

  const stalled = new FakePool({ hangQuery: true });
  const queryCatalog = new PostgresCatalog({ pool: stalled, connectTimeoutMs: 200, queryTimeoutMs: 100, statementTimeoutMs: 100 });
  const queryStarted = Date.now();
  await assert.rejects(queryCatalog.ready(), (error) => error.message === 'catalog_unavailable' && error.code === 'catalog_postgres_query_timeout');
  assert.ok(Date.now() - queryStarted < 1000);
  assert.ok(stalled.releaseError instanceof Error, 'timed-out client must be discarded');
  await queryCatalog.close();
});

test('ambiguous COMMIT acknowledgement retains RAW and reconciles the committed proposal', async () => {
  const pool = new FakePool();
  const catalog = new PostgresCatalog({ pool });
  await catalog.ready();
  pool.loseNextCommitAck = true;
  const rawStore = new MemoryRawStore({ encryptionKey: crypto.randomBytes(32).toString('base64') });
  const store = new FabricStore({ rawStore, catalog });
  const input = { actor: 'vitae', scope: 'shared', text: 'commit outcome must reconcile', idempotencyKey: 'ambiguous-commit-1' };

  const accepted = await store.propose(input);
  assert.equal(accepted.duplicate, false);
  assert.equal(pool.proposals.size, 1);
  assert.equal(rawStore.blobs.size, 1, 'committed catalog reference must retain encrypted RAW');
  const readable = await store.readProposal(accepted.id);
  assert.equal(readable.payload.text, input.text);
  const retry = await store.propose(input);
  assert.equal(retry.id, accepted.id);
  assert.equal(retry.duplicate, true);
  assert.ok(pool.releaseError instanceof Error, 'ambiguous COMMIT client must be discarded');
  await store.close();
});

test('proven non-commit conservatively retains the encrypted orphan', async () => {
  const pool = new FakePool();
  const catalog = new PostgresCatalog({ pool });
  await catalog.ready();
  pool.failNextProposalInsert = true;
  const rawStore = new MemoryRawStore({ encryptionKey: crypto.randomBytes(32).toString('base64') });
  const store = new FabricStore({ rawStore, catalog });
  await assert.rejects(
    store.propose({ actor: 'vitae', scope: 'shared', text: 'rollback cleanup', idempotencyKey: 'rollback-cleanup-1' }),
    /catalog_unavailable/
  );
  assert.equal(rawStore.blobs.size, 1);
  await store.close();
});

test('PostgreSQL catalog refuses a schema newer than this binary', async () => {
  const pool = new FakePool({ schemaVersion: POSTGRES_SCHEMA_VERSION + 1 });
  const catalog = new PostgresCatalog({ pool });
  await assert.rejects(catalog.ready(), /catalog_schema_version_unsupported/);
  assert.ok(pool.queries.some((entry) => entry.text === 'ROLLBACK'));
  await catalog.close();
});

test('PostgreSQL reciprocal merges acquire the same direction-independent pair lock', async () => {
  const pool = new FakePool();
  const catalog = new PostgresCatalog({ pool });
  const event = {
    id: 'event-pair', identityId: 'identity-a', revision: 2, operation: 'merge', targetIdentityId: 'identity-b',
    evidenceContentId: 'e'.repeat(64), evidenceStrength: 'strong', automatic: false, actorTag: 'actor-tag',
    idempotencyTag: 'idem-pair', response: { id: 'identity-a', kind: 'person', status: 'merged', canonicalIdentityId: 'identity-b', revision: 2 },
    createdAt: '2026-07-11T12:00:00.000Z'
  };
  await assert.rejects(catalog.mutateIdentity({ sourceId: 'identity-a', targetId: 'identity-b', expectedRevision: 1, operation: 'merge', event, rawRecord: raw('e'.repeat(64)) }), /identity_not_found/);
  const first = pool.queries.find(entry => entry.text.includes('hashtextextended($1, 1)'));
  assert.deepEqual(first.values, [identityPairLockKey('identity-a', 'identity-b')]);
  assert.match(first.values[0], /^[a-f0-9]{64}$/);
  assert.equal(first.values[0].includes('\u0000'), false);
  pool.queries.length = 0;
  await assert.rejects(catalog.mutateIdentity({ sourceId: 'identity-b', targetId: 'identity-a', expectedRevision: 1, operation: 'merge', event: { ...event, id: 'event-pair-reverse', identityId: 'identity-b', targetIdentityId: 'identity-a', idempotencyTag: 'idem-pair-reverse' }, rawRecord: raw('f'.repeat(64)) }), /identity_not_found/);
  const reverse = pool.queries.find(entry => entry.text.includes('hashtextextended($1, 1)'));
  assert.deepEqual(reverse.values, first.values);
  await catalog.close();
});

test('PostgreSQL decision supersession rewrites only review_required and audits it as superseded', async () => {
  const pool = new FakePool(); const catalog = new PostgresCatalog({ pool });
  const queued = proposal('proposal-supersede-pg', 'e'.repeat(64));
  await catalog.enqueueProposalWithRaw(queued, raw('e'.repeat(64)));
  const review = {
    kind: 'decision', proposalId: queued.id, proposalScope: 'shared:global', decisionId: 'decision-review-pg', status: 'review_required',
    decisionDigest: '4'.repeat(64), proposalDigest: '5'.repeat(64), policyDigest: '6'.repeat(64), timestamp: '2026-07-12T12:00:00Z'
  };
  const audit = suffix => ({ id: `audit-supersede-${suffix}`, ts: '2026-07-12T12:00:00Z', actorTag: 'actor-tag', action: 'curation_decision_receipt', requestId: suffix, targetId: queued.id, details: {} });
  assert.equal((await catalog.recordCuratorReceipt(review, audit('review'))).status, 'review_required');

  const approved = { ...review, decisionId: 'decision-approved-pg', status: 'approved_pending_apply', decisionDigest: '7'.repeat(64) };
  const result = await catalog.recordCuratorReceipt(approved, audit('approve'));
  assert.equal(result.status, 'approved_pending_apply');
  assert.equal(result.duplicate, false);
  assert.equal(result.superseded, true);
  assert.equal(result.decision.decisionId, 'decision-approved-pg');
  assert.equal(pool.curatorReceipts.get(queued.id).apply_json, null);
  assert.equal(pool.auditEvents.get('audit-supersede-approve')[4], 'superseded');

  await assert.rejects(catalog.recordCuratorReceipt(review, audit('replay-old')), /conflict/);
  assert.equal((await catalog.recordCuratorReceipt(approved, audit('replay-new'))).duplicate, true);
  const flip = { ...review, decisionId: 'decision-flip-pg', status: 'rejected', decisionDigest: '8'.repeat(64) };
  await assert.rejects(catalog.recordCuratorReceipt(flip, audit('flip')), /conflict/);
});
