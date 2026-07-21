import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import pg from 'pg';

import { createConversationEvent } from '../src/conversation-event-v3.mjs';
import { PostgresConversationArchive, SqliteConversationArchive } from '../src/conversation-archive-v1.mjs';

const KEY = Buffer.alloc(32, 7);
const TAG = `hmac-sha256:scope-v1:${'1'.repeat(64)}`;
const FIXTURE = JSON.parse(fs.readFileSync(new URL('./fixtures/conversation-archive-v1.conformance.json', import.meta.url), 'utf8'));
const fixtureIds = FIXTURE.scenarios.map(item => item.id);
const expires = new Map([
  ['cevt_archive0004', '2026-01-02T03:06:00Z'],
  ['cevt_archive0005', '2026-01-02T03:06:01Z'],
  ['cevt_tombstone0001', '2026-01-02T03:06:00Z']
]);

function event(reference, overrides = {}) {
  const payload = { eventId: reference.eventId, conversationId: reference.conversationId, sourceInstanceId: 'src_archive0001', role: 'user', visibleText: `synthetic ${reference.eventId}`,
    sourceOccurredAt: reference.sourceOccurredAt, occurredAt: reference.sourceOccurredAt, ordering: { sourceSequence: reference.sourceSequence }, direction: 'inbound', conversationKind: 'session', authorizationContextTags: { conversation: [TAG] }, state: reference.state, revision: reference.state === 'edited' || reference.state === 'replacement' ? 2 : 1, ...overrides };
  if (payload.state === 'tombstone') delete payload.visibleText;
  return createConversationEvent(payload, { keyId: 'synthetic-key', key: KEY, sentAt: '2026-01-02T03:04:06Z', nonce: `nonce_${reference.eventId.slice(-32)}`.padEnd(16, 'x') });
}
function options(extra = {}) { return { cursorKey: Buffer.alloc(32, 9), resolveIntegrityKey: id => id === 'synthetic-key' ? KEY : null, resolveExpiresAt: item => expires.get(item.eventId) ?? '2026-02-01T00:00:00Z', ...extra }; }
async function bounded(promise, timeoutMs, code) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(code)), timeoutMs); })
    ]);
  } finally { clearTimeout(timer); }
}
function clean(result) { return JSON.parse(JSON.stringify(result)); }
const scenario = id => FIXTURE.scenarios.find(item => item.id === id);
function projectionOf(value) { return { eventId: value.eventId, conversationId: value.conversationId, logicalDigest: value.logicalDigest, payloadDigest: value.integrity.payloadDigest, sourceOccurredAt: value.sourceOccurredAt, sourceSequence: value.ordering.sourceSequence, state: value.state }; }
function assertFixtureResult(id, actual, expectedResult, auditBefore, auditRows) {
  const expected = scenario(id).expected;
  assert.deepEqual(actual, expectedResult);
  if (expected.audit.required && expected.audit.outcome === 'recorded') {
    assert.equal(auditRows.length, auditBefore + 1, `${id} must append its required audit row`);
    assert.equal(auditRows.at(-1).action, expected.audit.action); assert.equal(auditRows.at(-1).outcome, expected.audit.outcome);
  }
  if (expected.audit.outcome === 'absent' || expected.audit.outcome === 'unavailable') assert.equal(auditRows.length, auditBefore, `${id} must not commit an audit row`);
}

async function scenarios(name, create) {
  await test(name, async t => {
    const archive = await create();
    t.after(async () => archive.close());
    assert.deepEqual(fixtureIds, ['commit', 'rollback', 'replay', 'changed_payload_conflict', 'ordering', 'pagination_cursor_binding', 'tombstone_visibility', 'retention_boundary', 'audit_outage']);

    const signed = new Map();
    const sign = (reference, overrides) => { const value = event(reference, overrides); signed.set(value.eventId, value); return value; };
    const fixtureProjection = reference => projectionOf(signed.get(reference.eventId));
    const reset = async () => {
      if (archive.db) archive.db.exec('DELETE FROM conversation_archive_audit_v1; DELETE FROM conversation_archive_conflicts_v1; DELETE FROM conversation_archive_requests_v1; DELETE FROM conversation_archive_events_v1');
      else await archive.pool.query('TRUNCATE agent_memory_fabric.conversation_archive_audit_v1, agent_memory_fabric.conversation_archive_conflicts_v1, agent_memory_fabric.conversation_archive_requests_v1, agent_memory_fabric.conversation_archive_events_v1');
    };
    await t.test('commit', async () => { const input = scenario('commit').request; const accepted = sign(input.event); const before = (await archive.auditRows()).length; const response = await archive.append(accepted, input.idempotencyKey); assertFixtureResult('commit', response, { outcome: 'stored', stateChanged: true, items: [], nextCursor: null }, before, await archive.auditRows()); });
    await t.test('rollback', async () => { const input = scenario('rollback').request; const attempted = sign(input.event); const before = (await archive.auditRows()).length; archive.fault = { transaction: true }; const response = await archive.append(attempted, input.idempotencyKey); archive.fault = null; assertFixtureResult('rollback', response, scenario('rollback').expected.result, before, await archive.auditRows()); assert.equal((await archive.list(input.event.conversationId, 100, false)).items.some(x => x.eventId === input.event.eventId), false); });
    await t.test('replay', async () => { const input = scenario('replay').request; const before = (await archive.auditRows()).length; const response = await archive.append(signed.get(input.event.eventId), input.idempotencyKey); assertFixtureResult('replay', response, scenario('replay').expected.result, before, await archive.auditRows()); });
    await t.test('changed_payload_conflict', async () => {
      const input = scenario('changed_payload_conflict').request; const changed = event(input.event, { occurredAt: '2026-01-02T03:04:06Z' }); const before = (await archive.auditRows()).length;
      const response = await archive.append(changed, input.idempotencyKey); const existing = signed.get(input.event.eventId); assertFixtureResult('changed_payload_conflict', response, { outcome: 'conflict_visible', stateChanged: false, items: [], nextCursor: null, conflict: { eventId: existing.eventId, logicalDigest: changed.logicalDigest, existingPayloadDigest: existing.integrity.payloadDigest, receivedPayloadDigest: changed.integrity.payloadDigest } }, before, await archive.auditRows()); assert.equal(JSON.stringify(response).includes('synthetic'), false);
      assert.equal(await archive.conflictEvidenceCount(), 1);
    });
    await t.test('ordering', async () => {
      await reset(); const expected = scenario('ordering').expected.result.items; const committed = sign(scenario('commit').request.event); await archive.append(committed, 'cai_commit0001'); await archive.append(sign(expected[0]), 'cai_order0003'); await archive.append(sign(expected[2]), 'cai_order0004');
      const input = scenario('ordering').request; const listed = await archive.list(input.conversationId, input.limit, input.includeTombstones); assert.deepEqual(listed, { ...scenario('ordering').expected.result, items: expected.map(fixtureProjection) });
    });
    await t.test('pagination_cursor_binding', async () => { await reset(); const input = scenario('pagination_cursor_binding').request; await archive.append(sign(scenario('commit').request.event), 'cai_commit0001'); await archive.append(sign(scenario('ordering').expected.result.items[0]), 'cai_order0003'); const first = await archive.list(input.conversationId, input.limit, input.includeTombstones); assert.ok(first.nextCursor); const response = await archive.list(scenario('pagination_cursor_binding').cursorBinding.conversationId, input.limit, input.includeTombstones, first.nextCursor); assert.deepEqual(response, scenario('pagination_cursor_binding').expected.result); });
    await t.test('tombstone_visibility', async () => { await reset(); const entry = scenario('tombstone_visibility'); const target = sign(scenario('commit').request.event); await archive.append(target, 'cai_commit0001'); const tombstone = sign(entry.tombstoneVisibility.includedTombstone, { tombstonesEventId: target.eventId }); await archive.tombstone(tombstone, 'cai_tombstone01'); const ordinary = await archive.list(entry.request.conversationId, entry.request.limit, false); assert.deepEqual(ordinary.items, entry.tombstoneVisibility.ordinaryItems); const included = await archive.list(entry.request.conversationId, entry.request.limit, entry.request.includeTombstones); assert.deepEqual(included, { ...entry.expected.result, items: [fixtureProjection(entry.tombstoneVisibility.includedTombstone)] }); });
    await t.test('retention_boundary', async () => { await reset(); const entry = scenario('retention_boundary'); const target = sign(scenario('commit').request.event); await archive.append(target, 'cai_commit0001'); const expired = sign(entry.retentionBoundary.expiredAtCutoff.event, { tombstonesEventId: target.eventId }); const retained = sign(entry.retentionBoundary.retainedAfterCutoff.event); expires.set(expired.eventId, entry.retentionBoundary.expiredAtCutoff.expiresAt); expires.set(retained.eventId, entry.retentionBoundary.retainedAfterCutoff.expiresAt); await archive.tombstone(expired, 'cai_retainedtomb01'); await archive.append(retained, 'cai_retainedlive01'); const before = (await archive.auditRows()).length; const response = await archive.applyRetention(entry.request.cutoff, entry.request.limit, entry.request.idempotencyKey); assertFixtureResult('retention_boundary', response, entry.expected.result, before, await archive.auditRows()); assert.equal((await archive.list(entry.request.conversationId, 20, false)).items.some(x => x.eventId === target.eventId), false, 'expired tombstone must not resurrect its target'); });
    await t.test('audit_outage', async () => { await reset(); const entry = scenario('audit_outage'); const attempted = sign(entry.request.event); const before = (await archive.auditRows()).length; archive.fault = { audit: true }; const response = await archive.append(attempted, entry.request.idempotencyKey); archive.fault = null; assertFixtureResult('audit_outage', response, entry.expected.result, before, await archive.auditRows()); assert.equal((await archive.list(entry.request.event.conversationId, 20, false)).items.some(x => x.eventId === attempted.eventId), false); });
    await t.test('cross-reference rejection and content-free invalid errors', async () => { const foreign = event({ eventId: 'cevt_foreign0001', conversationId: 'ccon_archive0002', sourceOccurredAt: '2026-01-02T03:04:05Z', sourceSequence: 1, state: 'active' }); await archive.append(foreign, 'cai_foreign0001'); const cross = event({ eventId: 'cevt_crossref0001', conversationId: 'ccon_archive0001', sourceOccurredAt: '2026-01-02T03:04:06Z', sourceSequence: 2, state: 'replacement' }, { replacesEventId: foreign.eventId }); assert.deepEqual(clean(await archive.append(cross, 'cai_crossref0001')), { outcome: 'request_invalid', stateChanged: false, items: [], nextCursor: null }); });
    await t.test('refreshed envelope retries require the same cai key', async () => { await reset(); const first = event({ eventId: 'cevt_refreshretry01', conversationId: 'ccon_archive0001', sourceOccurredAt: '2026-01-02T03:04:05Z', sourceSequence: 1, state: 'active' }); const { schema, logicalDigest, integrity, ...payload } = first; const refreshed = createConversationEvent(payload, { keyId: 'synthetic-key', key: KEY, sentAt: '2026-01-02T03:04:07Z', nonce: 'refreshed_nonce_01' }); assert.equal((await archive.append(first, 'cai_refreshretry01')).outcome, 'stored'); assert.equal((await archive.append(refreshed, 'cai_refreshretry01')).outcome, 'duplicate'); assert.equal((await archive.append(refreshed, 'cai_refreshretry02')).outcome, 'conflict_visible'); });
    await t.test('duplicate replays append audits and fail closed when the audit is unavailable', async () => {
      await reset();
      const first = event({ eventId: 'cevt_duplicateaudit1', conversationId: 'ccon_archive0001', sourceOccurredAt: '2026-01-02T03:04:05Z', sourceSequence: 1, state: 'active' });
      expires.set(first.eventId, '2026-01-02T03:05:00Z');
      assert.equal((await archive.append(first, 'cai_duplicateaudit1')).outcome, 'stored');
      const beforeAppendReplay = (await archive.auditRows()).length;
      assert.equal((await archive.append(first, 'cai_duplicateaudit1')).outcome, 'duplicate');
      assert.equal((await archive.auditRows()).length, beforeAppendReplay + 1);
      assert.equal((await archive.applyRetention('2026-01-02T03:05:00Z', 1, 'cai_duplicateaudit2')).outcome, 'retention_expired');
      const beforeRetentionReplay = (await archive.auditRows()).length;
      assert.equal((await archive.applyRetention('2026-01-02T03:05:00Z', 1, 'cai_duplicateaudit2')).outcome, 'duplicate');
      assert.equal((await archive.auditRows()).length, beforeRetentionReplay + 1);
      archive.fault = { audit: true };
      assert.equal((await archive.applyRetention('2026-01-02T03:05:00Z', 1, 'cai_duplicateaudit2')).outcome, 'audit_unavailable');
      archive.fault = null;
      assert.equal((await archive.auditRows()).length, beforeRetentionReplay + 1);
    });
    await t.test('replacement chains hide immutable targets permanently', async () => { await reset(); const base = event({ eventId: 'cevt_replacebase01', conversationId: 'ccon_archive0001', sourceOccurredAt: '2026-01-02T03:04:05Z', sourceSequence: 1, state: 'active' }); const edited = event({ eventId: 'cevt_replaceedit01', conversationId: 'ccon_archive0001', sourceOccurredAt: '2026-01-02T03:04:06Z', sourceSequence: 2, state: 'edited' }, { replacesEventId: base.eventId }); const current = event({ eventId: 'cevt_replacefinal1', conversationId: 'ccon_archive0001', sourceOccurredAt: '2026-01-02T03:04:07Z', sourceSequence: 3, state: 'replacement' }, { replacesEventId: edited.eventId }); expires.set(edited.eventId, '2026-01-02T03:08:00Z'); expires.set(current.eventId, '2026-01-02T03:08:00Z'); assert.equal((await archive.append(base, 'cai_replacebase01')).outcome, 'stored'); assert.equal((await archive.append(edited, 'cai_replaceedit01')).outcome, 'stored'); assert.equal((await archive.append(current, 'cai_replacefinal1')).outcome, 'stored'); assert.deepEqual((await archive.list(base.conversationId, 10, false)).items, [projectionOf(current)]); assert.deepEqual((await archive.list(base.conversationId, 10, true)).items, [projectionOf(current)]); await archive.applyRetention('2026-01-02T03:08:00Z', 10, 'cai_replaceexpire1'); assert.deepEqual((await archive.list(base.conversationId, 10, false)).items, []); });
  });
}

const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-archive-'));
const sqlitePath = path.join(temporary, 'archive.sqlite');
await scenarios('SQLite archive adapter shared conformance', async () => new SqliteConversationArchive({ filename: sqlitePath, ...options() }));
const syntheticReference = eventId => ({ eventId, conversationId: 'ccon_archive0001', sourceOccurredAt: '2026-01-02T03:04:05Z', sourceSequence: 1, state: 'active' });
test('SQLite restart persistence', () => { const first = new SqliteConversationArchive({ filename: sqlitePath, ...options() }); first.append(event(syntheticReference('cevt_restart0001')), 'cai_restart0001'); first.close(); const second = new SqliteConversationArchive({ filename: sqlitePath, ...options() }); assert.equal(second.list('ccon_archive0001', 100, true).items.some(item => item.eventId === 'cevt_restart0001'), true); second.close(); });
test('cursor key and dependencies are checked before PostgreSQL pool creation', () => { let calls = 0; const poolFactory = () => { calls += 1; throw new Error('must not connect'); }; assert.throws(() => new PostgresConversationArchive({ poolFactory, resolveIntegrityKey: () => KEY, resolveExpiresAt: () => '2026-02-01T00:00:00Z' }), /cursor_key_invalid/); assert.throws(() => new PostgresConversationArchive({ poolFactory, cursorKey: Buffer.alloc(32), resolveExpiresAt: () => '2026-02-01T00:00:00Z' }), /integrity_key_resolver_invalid/); assert.equal(calls, 0); });
test('cursor key is mandatory and cursors page before rejecting tampering', () => { assert.throws(() => new SqliteConversationArchive({}), /cursor_key_invalid/); const archive = new SqliteConversationArchive(options()); const firstEvent = event(syntheticReference('cevt_cursor0001')); const secondEvent = event({ ...syntheticReference('cevt_cursor0002'), sourceSequence: 2 }); archive.append(firstEvent, 'cai_cursor0001'); archive.append(secondEvent, 'cai_cursor0002'); const cursor = archive.list('ccon_archive0001', 1, false).nextCursor; assert.deepEqual(archive.list('ccon_archive0001', 1, false, cursor).items, [projectionOf(secondEvent)]); const changed = `${cursor.slice(0, -1)}${cursor.endsWith('A') ? 'B' : 'A'}`; assert.deepEqual(archive.list('ccon_archive0001', 1, false, changed), { outcome: 'cursor_binding_invalid', stateChanged: false, items: [], nextCursor: null }); archive.close(); });
test('maximum-length opaque identifiers fit a real protected cursor', () => { const archive = new SqliteConversationArchive(options()); const conversationId = `ccon_${'a'.repeat(128)}`; const first = event({ eventId: `cevt_${'b'.repeat(128)}`, conversationId, sourceOccurredAt: '2026-01-02T03:04:05Z', sourceSequence: 1, state: 'active' }); const second = event({ eventId: `cevt_${'c'.repeat(128)}`, conversationId, sourceOccurredAt: '2026-01-02T03:04:05Z', sourceSequence: 2, state: 'active' }); archive.append(first, `cai_${'d'.repeat(128)}`); archive.append(second, `cai_${'e'.repeat(128)}`); const firstPage = archive.list(conversationId, 1, false); assert.ok(firstPage.nextCursor.length > 256); assert.deepEqual(archive.list(conversationId, 1, false, firstPage.nextCursor).items, [projectionOf(second)]); archive.close(); });
test('actual SQLite audit insert failure rolls back as audit_unavailable', () => { const archive = new SqliteConversationArchive(options()); archive.db.exec('DROP TABLE conversation_archive_audit_v1'); const response = archive.append(event(syntheticReference('cevt_auditinsert01')), 'cai_auditinsert01'); assert.deepEqual(response, { outcome: 'audit_unavailable', stateChanged: false, items: [], nextCursor: null }); assert.equal(archive.list('ccon_archive0001', 20, false).items.some(item => item.eventId === 'cevt_auditinsert01'), false); archive.close(); });
test('SQLite visibility query handles a chain beyond the parameter ceiling without resurrection', () => {
  const archive = new SqliteConversationArchive(options());
  const conversationId = 'ccon_longchain0001';
  let previous = event({ eventId: 'cevt_chain0000000', conversationId, sourceOccurredAt: '2026-01-02T03:04:05Z', sourceSequence: 1, state: 'active' });
  assert.equal(archive.append(previous, 'cai_chain0000000').outcome, 'stored');
  for (let index = 1; index <= 1_050; index += 1) {
    const suffix = String(index).padStart(7, '0');
    const current = event({ eventId: `cevt_chain${suffix}`, conversationId, sourceOccurredAt: '2026-01-02T03:04:06Z', sourceSequence: index + 1, state: 'replacement' }, { replacesEventId: previous.eventId });
    assert.equal(archive.append(current, `cai_chain${suffix}`).outcome, 'stored');
    previous = current;
  }
  const removal = event({ eventId: 'cevt_chainremove1', conversationId, sourceOccurredAt: '2026-01-02T03:24:00Z', sourceSequence: 2_000, state: 'tombstone' }, { tombstonesEventId: previous.eventId });
  assert.equal(archive.tombstone(removal, 'cai_chainremove1').outcome, 'stored');
  assert.deepEqual(archive.list(conversationId, 100, false).items, []);
  assert.deepEqual(archive.list(conversationId, 100, true).items.map(item => item.eventId), [removal.eventId]);
  archive.close();
});
test('PostgreSQL initialization, connection, and query failures normalize to archive results', async () => {
  const initialFailure = new PostgresConversationArchive({
    pool: { async query() { throw new Error('initialization'); }, async connect() { throw new Error('unexpected'); }, async end() {} },
    ...options()
  });
  const input = event(syntheticReference('cevt_pgfailure0001'));
  assert.equal((await initialFailure.append(input, 'cai_pgfailure0001')).outcome, 'transaction_rolled_back');
  assert.equal((await initialFailure.tombstone(input, 'cai_pgfailure0001')).outcome, 'request_invalid');
  assert.equal((await initialFailure.list(input.conversationId, 1, false)).outcome, 'transaction_rolled_back');
  assert.equal((await initialFailure.applyRetention('2026-01-02T03:05:00Z', 1, 'cai_pgfailure0002')).outcome, 'transaction_rolled_back');
  await initialFailure.close();
  const connectionFailure = new PostgresConversationArchive({
    pool: { async query() { return { rows: [] }; }, async connect() { throw new Error('connection'); }, async end() {} },
    ...options()
  });
  assert.equal((await connectionFailure.append(input, 'cai_pgfailure0003')).outcome, 'transaction_rolled_back');
  await connectionFailure.close();
  let poolQueries = 0;
  const queryFailure = new PostgresConversationArchive({
    pool: {
      async query() { poolQueries += 1; if (poolQueries === 1) return { rows: [] }; throw new Error('query'); },
      async connect() { return { async query() { throw new Error('query'); }, release() {} }; },
      async end() {}
    },
    ...options()
  });
  assert.equal((await queryFailure.append(input, 'cai_pgfailure0004')).outcome, 'transaction_rolled_back');
  assert.equal((await queryFailure.list(input.conversationId, 1, false)).outcome, 'transaction_rolled_back');
  await queryFailure.close();
});
test('PostgreSQL lazy initialization resets after one shared transient failure and caches success', async () => {
  let ddlAttempts = 0;
  const archive = new PostgresConversationArchive({
    pool: {
      async query() {
        ddlAttempts += 1;
        if (ddlAttempts === 1) throw new Error('transient initialization failure');
        return { rows: [] };
      },
      async connect() { throw new Error('not reached'); },
      async end() {}
    },
    ...options()
  });

  const first = await Promise.allSettled([archive.ready(), archive.ready(), archive.ready()]);
  assert.deepEqual(first.map(item => item.status), ['rejected', 'rejected', 'rejected']);
  assert.equal(ddlAttempts, 1);

  const second = await Promise.all([archive.ready(), archive.ready(), archive.ready()]);
  assert.equal(second.every(item => item === archive), true);
  assert.equal(ddlAttempts, 2);

  await archive.ready();
  assert.equal(ddlAttempts, 2);
  await archive.close();
});
test('PostgreSQL append retries only after a later initialization attempt recovers', async () => {
  let ddlAttempts = 0;
  let stored = null;
  const client = {
    async query(sql, values = []) {
      if (sql === 'BEGIN' || sql === 'COMMIT' || sql === 'ROLLBACK' || sql.startsWith('SELECT pg_advisory')) return { rows: [] };
      if (sql.startsWith('SELECT * FROM agent_memory_fabric.conversation_archive_requests_v1')) return { rows: [] };
      if (sql.startsWith('SELECT * FROM agent_memory_fabric.conversation_archive_events_v1')) return { rows: [] };
      if (sql.startsWith('INSERT INTO agent_memory_fabric.conversation_archive_events_v1')) {
        stored = {
          event_id: values[0], conversation_id: values[1], source_instance_id: values[2], state: values[3],
          logical_digest: values[4], payload_digest: values[5], source_occurred_at: values[6],
          source_time_key: values[7], source_sequence: values[8]
        };
      }
      return { rows: [] };
    },
    release() {}
  };
  const archive = new PostgresConversationArchive({
    pool: {
      async query(sql) {
        if (sql.includes('CREATE SCHEMA IF NOT EXISTS')) {
          ddlAttempts += 1;
          if (ddlAttempts === 1) throw new Error('transient initialization failure');
          return { rows: [] };
        }
        if (sql.startsWith('SELECT e.*')) return { rows: stored ? [stored] : [] };
        throw new Error('unexpected pool query');
      },
      async connect() { return client; },
      async end() {}
    },
    ...options()
  });
  const input = event(syntheticReference('cevt_pgretryappend1'));

  assert.deepEqual(await archive.append(input, 'cai_pgretryappend1'), { outcome: 'transaction_rolled_back', stateChanged: false, items: [], nextCursor: null });
  assert.equal(ddlAttempts, 1);
  assert.deepEqual(await archive.append(input, 'cai_pgretryappend1'), { outcome: 'stored', stateChanged: true, items: [], nextCursor: null });
  assert.equal(ddlAttempts, 2);
  assert.deepEqual((await archive.list(input.conversationId, 1, false)).items, [projectionOf(input)]);
  await archive.ready();
  assert.equal(ddlAttempts, 2);
  await archive.close();
});

if (process.env.AMF_ARCHIVE_POSTGRES_TEST_URL) {
  await scenarios('PostgreSQL archive adapter shared conformance', async () => {
    const archive = new PostgresConversationArchive({ connectionString: process.env.AMF_ARCHIVE_POSTGRES_TEST_URL, ...options() }); await archive.ready(); await archive.pool.query('TRUNCATE agent_memory_fabric.conversation_archive_audit_v1, agent_memory_fabric.conversation_archive_conflicts_v1, agent_memory_fabric.conversation_archive_requests_v1, agent_memory_fabric.conversation_archive_events_v1'); return archive;
  });
  test('PostgreSQL ready retries one pre-DDL transient failure and then remains cached', async () => {
    const realPool = new pg.Pool({ connectionString: process.env.AMF_ARCHIVE_POSTGRES_TEST_URL, max: 1 });
    let ddlAttempts = 0;
    const pool = {
      query: async (...args) => {
        if (typeof args[0] === 'string' && args[0].includes('CREATE SCHEMA IF NOT EXISTS')) {
          ddlAttempts += 1;
          if (ddlAttempts === 1) throw new Error('synthetic_pre_ddl_failure');
        }
        return realPool.query(...args);
      },
      connect: (...args) => realPool.connect(...args),
      end: () => realPool.end()
    };
    const archive = new PostgresConversationArchive({ pool, ...options() });
    try {
      await assert.rejects(archive.ready(), /synthetic_pre_ddl_failure/);
      await archive.ready();
      await archive.ready();
      assert.equal(ddlAttempts, 2);
    } finally {
      await archive.close();
    }
  });
  test('PostgreSQL max-1 pool recovers an ambiguous committed append acknowledgement', async () => {
    const realPool = new pg.Pool({ connectionString: process.env.AMF_ARCHIVE_POSTGRES_TEST_URL, max: 1 });
    let failAfterCommit = true;
    const pool = {
      query: (...args) => realPool.query(...args),
      end: () => realPool.end(),
      connect: async () => {
        const client = await realPool.connect();
        return new Proxy(client, { get(target, property) {
        if (property === 'query') return async (...args) => {
          const response = await target.query(...args);
          if (failAfterCommit && args[0] === 'COMMIT') { failAfterCommit = false; throw new Error('synthetic_commit_ack_lost'); }
          return response;
        };
        const value = target[property]; return typeof value === 'function' ? value.bind(target) : value;
        } });
      }
    };
    const archive = new PostgresConversationArchive({ pool, ...options() });
    try {
      await archive.ready();
      await pool.query('TRUNCATE agent_memory_fabric.conversation_archive_audit_v1, agent_memory_fabric.conversation_archive_conflicts_v1, agent_memory_fabric.conversation_archive_requests_v1, agent_memory_fabric.conversation_archive_events_v1');
      const input = event(syntheticReference('cevt_ambiguouscommit01'));
      const bounded = Promise.race([
        archive.append(input, 'cai_ambiguouscommit01'),
        new Promise((_, reject) => setTimeout(() => reject(new Error('ambiguous_commit_timeout')), 2_000))
      ]);
      assert.deepEqual(await bounded, { outcome: 'duplicate', stateChanged: false, items: [], nextCursor: null });
      const counts = (await pool.query(`SELECT
        (SELECT count(*) FROM agent_memory_fabric.conversation_archive_events_v1) AS events,
        (SELECT count(*) FROM agent_memory_fabric.conversation_archive_requests_v1) AS requests,
        (SELECT count(*) FROM agent_memory_fabric.conversation_archive_audit_v1) AS audits`)).rows[0];
      assert.deepEqual(counts, { events: '1', requests: '1', audits: '1' });
    } finally { await archive.close(); }
  });
  test('PostgreSQL ambiguous committed conflict returns conflict_visible', async () => {
    const realPool = new pg.Pool({ connectionString: process.env.AMF_ARCHIVE_POSTGRES_TEST_URL, max: 1 });
    let failAfterCommit = false;
    const pool = {
      query: (...args) => realPool.query(...args),
      end: () => realPool.end(),
      connect: async () => {
        const client = await realPool.connect();
        return new Proxy(client, { get(target, property) {
          if (property === 'query') return async (...args) => {
            const response = await target.query(...args);
            if (failAfterCommit && args[0] === 'COMMIT') { failAfterCommit = false; throw new Error('synthetic_conflict_ack_lost'); }
            return response;
          };
          const value = target[property];
          return typeof value === 'function' ? value.bind(target) : value;
        } });
      }
    };
    const archive = new PostgresConversationArchive({ pool, ...options() });
    try {
      await archive.ready();
      await pool.query('TRUNCATE agent_memory_fabric.conversation_archive_audit_v1, agent_memory_fabric.conversation_archive_conflicts_v1, agent_memory_fabric.conversation_archive_requests_v1, agent_memory_fabric.conversation_archive_events_v1');
      const original = event(syntheticReference('cevt_ambiguousconflict1'));
      const changed = event(syntheticReference('cevt_ambiguousconflict1'), { occurredAt: '2026-01-02T03:04:06Z' });
      assert.equal((await archive.append(original, 'cai_ambiguousconflict1')).outcome, 'stored');
      failAfterCommit = true;
      const response = await Promise.race([
        archive.append(changed, 'cai_ambiguousconflict2'),
        new Promise((_, reject) => setTimeout(() => reject(new Error('ambiguous_conflict_timeout')), 2_000))
      ]);
      assert.deepEqual(response, { outcome: 'conflict_visible', stateChanged: false, items: [], nextCursor: null, conflict: { eventId: changed.eventId, logicalDigest: changed.logicalDigest, existingPayloadDigest: original.integrity.payloadDigest, receivedPayloadDigest: changed.integrity.payloadDigest } });
      assert.equal(await archive.conflictEvidenceCount(), 1);
    } finally { await archive.close(); }
  });
  test('PostgreSQL max-1 pool recovers an ambiguous committed retention acknowledgement', async () => {
    const realPool = new pg.Pool({ connectionString: process.env.AMF_ARCHIVE_POSTGRES_TEST_URL, max: 1 });
    let failAfterCommit = false;
    const pool = {
      query: (...args) => realPool.query(...args),
      end: () => realPool.end(),
      connect: async () => {
        const client = await realPool.connect();
        return new Proxy(client, { get(target, property) {
          if (property === 'query') return async (...args) => {
            const response = await target.query(...args);
            if (failAfterCommit && args[0] === 'COMMIT') { failAfterCommit = false; throw new Error('synthetic_retention_ack_lost'); }
            return response;
          };
          const value = target[property];
          return typeof value === 'function' ? value.bind(target) : value;
        } });
      }
    };
    const archive = new PostgresConversationArchive({ pool, ...options() });
    try {
      await archive.ready();
      await pool.query('TRUNCATE agent_memory_fabric.conversation_archive_audit_v1, agent_memory_fabric.conversation_archive_conflicts_v1, agent_memory_fabric.conversation_archive_requests_v1, agent_memory_fabric.conversation_archive_events_v1');
      const input = event(syntheticReference('cevt_ambiguousretain1'));
      expires.set(input.eventId, '2026-01-02T03:05:00Z');
      assert.equal((await archive.append(input, 'cai_ambiguousretain1')).outcome, 'stored');
      failAfterCommit = true;
      assert.deepEqual(await bounded(archive.applyRetention('2026-01-02T03:05:00Z', 1, 'cai_ambiguousretain2'), 2_000, 'ambiguous_retention_timeout'), { outcome: 'duplicate', stateChanged: false, items: [], nextCursor: null });
      const counts = (await pool.query(`SELECT
        (SELECT count(*) FROM agent_memory_fabric.conversation_archive_requests_v1 WHERE idempotency_key='cai_ambiguousretain2' AND outcome='retention_expired' AND operation='apply_retention') AS requests,
        (SELECT count(*) FROM agent_memory_fabric.conversation_archive_audit_v1 WHERE action='apply_retention' AND outcome='recorded') AS audits,
        (SELECT count(*) FROM agent_memory_fabric.conversation_archive_events_v1 WHERE event_id='cevt_ambiguousretain1' AND expired=true) AS expired`)).rows[0];
      assert.deepEqual(counts, { requests: '1', audits: '1', expired: '1' });
    } finally { await archive.close(); }
  });
} else {
  test('PostgreSQL archive adapter shared conformance', { skip: 'set AMF_ARCHIVE_POSTGRES_TEST_URL to run against real PostgreSQL' }, () => {});
}
