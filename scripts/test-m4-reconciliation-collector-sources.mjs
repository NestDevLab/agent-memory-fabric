import assert from 'node:assert/strict';
import test from 'node:test';

import { createM4PostgresReconciliationCollector, createM4SqliteReconciliationCollector } from '../src/operator/m4-reconciliation-collector-sources.mjs';

const columns = ['event_id', 'state', 'logical_digest', 'payload_digest', 'source_occurred_at', 'event_json'];
const digest = char => `sha256:${char.repeat(64)}`;
const row = (n, state = 'active') => ({ event_id: `cevt_source${String(n).padStart(4, '0')}`, payload_digest: digest('a'), logical_digest: digest('b'), source_occurred_at: '2026-07-22T00:00:00Z', occurred_at: '2026-07-22T00:00:01Z', state, ...(state === 'edited' || state === 'replacement' ? { replaces_event_id: 'cevt_source0000' } : {}), ...(state === 'tombstone' ? { tombstones_event_id: 'cevt_source0000' } : {}), ...(state === 'conflict' ? { conflicts_with_event_ids: '["cevt_source0000"]' } : {}) });
async function read(source) { const rows = []; for await (const item of source.events) rows.push(item); await source.close(); return rows; }

test('sqlite uses one read transaction, keysets content-free projections, and derives a stable checkpoint', async () => {
  const calls = []; const rows = [row(1), row(2, 'edited'), row(3, 'replacement'), row(4, 'tombstone'), row(5, 'conflict')];
  const db = { exec(sql) { calls.push(sql); }, prepare(sql) { calls.push(sql); return { all(after = '', limit) { if (sql.startsWith('PRAGMA')) return columns.map(name => ({ name })); return rows.filter(value => value.event_id > after).slice(0, limit); } }; } };
  const source = createM4SqliteReconciliationCollector({ db, pageSize: 2 }); const revision = await source.revisionSource(); const values = await read(source);
  assert.equal(revision.state, 'complete'); assert.deepEqual(values.map(value => value.eventId), rows.map(value => value.event_id)); assert.equal(values[4].conflictsWithEventIds[0], 'cevt_source0000'); assert.equal(calls[0], 'BEGIN'); assert.equal(calls.at(-1), 'COMMIT');
  const text = calls.join('\n'); assert.equal(/visibleText|event_json\s+AS/i.test(text), false); assert.match(text, /ORDER BY event_id ASC/);
});

test('postgres uses repeatable-read, keysets, rollback/release on early close and commit on completion', async () => {
  const calls = []; const rows = [row(1), row(2)]; let released = 0;
  const client = { async query(sql, values = []) { calls.push({ sql, values }); if (sql.startsWith('SELECT column_name')) return { rows: columns.map(column_name => ({ column_name })) }; if (sql.startsWith('SELECT event_id')) return { rows: rows.filter(value => value.event_id > values[0]).slice(0, values[1]) }; return { rows: [] }; }, release() { released += 1; } };
  const source = createM4PostgresReconciliationCollector({ acquireClient: async () => client, pageSize: 1 }); await source.revisionSource(); await source.close(); assert.equal(calls.some(call => call.sql === 'ROLLBACK'), true); assert.equal(released, 1);
  const source2 = createM4PostgresReconciliationCollector({ acquireClient: async () => client, pageSize: 1 }); await source2.revisionSource(); assert.equal((await read(source2)).length, 2); assert.equal(calls.some(call => call.sql === 'COMMIT'), true); assert.equal(released, 2); assert.equal(calls.some(call => /BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY/.test(call.sql)), true); assert.equal(calls.filter(call => call.sql.startsWith('SELECT event_id')).every(call => !/visibleText|SELECT\s+[^,]*event_json/i.test(call.sql)), true);
});

test('source is fail-closed before revision, on duplicate lifecycle use, and on schema failure', async () => {
  const calls = []; const db = { exec(sql) { calls.push(sql); }, prepare(sql) { return { all() { return sql.startsWith('PRAGMA') ? [{ name: 'event_id' }] : []; } }; } };
  const source = createM4SqliteReconciliationCollector({ db, pageSize: 1 }); await assert.rejects(async () => { for await (const _ of source.events) {} }, { code: 'm4_reconciliation_collector_source_invalid' }); await assert.rejects(() => source.revisionSource(), { code: 'm4_reconciliation_collector_source_invalid' });
  assert.equal(calls.at(-1), 'ROLLBACK');
});

test('event scan must reproduce the revision event set inside the pinned transaction', async () => {
  const calls = []; let scan = 0; const revisions = [[row(1)], [row(2)]];
  const db = { exec(sql) { calls.push(sql); }, prepare(sql) { return { all(after = '', limit) {
    if (sql.startsWith('PRAGMA')) return columns.map(name => ({ name }));
    const values = revisions[Math.min(scan, revisions.length - 1)]; scan += 1;
    return values.filter(value => value.event_id > after).slice(0, limit);
  } }; } };
  const source = createM4SqliteReconciliationCollector({ db, pageSize: 10 }); await source.revisionSource();
  await assert.rejects(async () => { for await (const _ of source.events) {} },
    { code: 'm4_reconciliation_collector_source_invalid' });
  assert.equal(calls.at(-1), 'ROLLBACK'); await source.close();
});
