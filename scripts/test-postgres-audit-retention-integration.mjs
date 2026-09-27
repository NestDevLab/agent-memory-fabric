import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import { PostgresCatalog } from '../src/fabric-store.mjs';
import {
  AUDIT_RETENTION_TABLE, auditRetentionCutoff, buildPhaseAPredicate, classifyAuditEvent, isAuditRetentionExpired
} from '../src/audit-retention.mjs';
import { countAuditRowsByPair, previewPhaseA, runPhaseADeleteBatch } from '../src/audit-retention-cleanup.mjs';

const connectionString = String(process.env.AMF_TEST_POSTGRES_URL || '').trim();
const enabled = connectionString && process.env.AMF_TEST_POSTGRES_ALLOW_MUTATION === 'true';
const SCHEMA = 'agent_memory_fabric';
// Fixtures sit before this instant; rows other suites write (2026 timestamps) are never eligible.
const AS_OF = '2020-06-01T00:00:00.000Z';

const UNKNOWN_PAIRS = [
  ['totally_unknown_action', 'allowed'], ['memory_status', 'throttled'], ['memory_status', 'sampled'],
  ['authenticate', 'allowed'], ['raw_event_ingest', 'recovered']
];

async function snapshotSchemaTables(pool) {
  const tables = await pool.query(`SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = $1 AND c.relkind IN ('r','p') ORDER BY c.relname`, [SCHEMA]);
  const snapshot = {};
  for (const { relname } of tables.rows) {
    const quoted = `"${SCHEMA}"."${relname.replace(/"/g, '""')}"`;
    const result = await pool.query(`SELECT count(*)::bigint AS count, md5(coalesce(string_agg(t::text, '|' ORDER BY t::text), '')) AS digest FROM ${quoted} t`);
    snapshot[relname] = `${result.rows[0].count}:${result.rows[0].digest}`;
  }
  return snapshot;
}

test('Phase A predicate, preview, and bounded delete agree with the classifier on real PostgreSQL', { skip: !enabled }, async () => {
  const databaseName = decodeURIComponent(new URL(connectionString).pathname.replace(/^\//, ''));
  assert.match(databaseName, /(^|[-_])test($|[-_])/i, 'AMF_TEST_POSTGRES_URL must reference an isolated test database');
  const catalog = new PostgresCatalog({ connectionString, ssl: process.env.AMF_TEST_POSTGRES_SSL === 'disable' ? false : { rejectUnauthorized: true } });
  const prefix = `audit-retention-${crypto.randomUUID()}-`;
  try {
    await catalog.ready();
    const fixtures = [];
    let sequence = 0;
    const add = (action, outcome, ts) => fixtures.push({ id: `${prefix}${++sequence}`, action, outcome, ts: new Date(ts).toISOString() });
    for (const row of AUDIT_RETENTION_TABLE) {
      add(row.action, row.outcome, '2000-01-01T00:00:00.000Z');
      for (const retentionClass of ['ephemeral_status', 'ephemeral_operational', 'security_review']) {
        const cutoff = auditRetentionCutoff(retentionClass, AS_OF).getTime();
        for (const delta of [-1, 0, 1]) add(row.action, row.outcome, cutoff + delta);
      }
      add(row.action, row.outcome, AS_OF);
    }
    for (const [action, outcome] of UNKNOWN_PAIRS) {
      add(action, outcome, '2000-01-01T00:00:00.000Z');
      add(action, outcome, auditRetentionCutoff('ephemeral_status', AS_OF).getTime() - 1);
    }
    for (let offset = 0; offset < fixtures.length; offset += 500) {
      const chunk = fixtures.slice(offset, offset + 500);
      await catalog.pool.query({
        text: `INSERT INTO ${SCHEMA}.audit_events_v2(id,ts,actor_tag,action,outcome,details_json)
          SELECT id, ts::timestamptz, 'integration-actor', action, outcome, '{}'::jsonb
          FROM unnest($1::text[], $2::text[], $3::text[], $4::text[]) AS f(id, ts, action, outcome)`,
        values: [chunk.map(item => item.id), chunk.map(item => item.ts), chunk.map(item => item.action), chunk.map(item => item.outcome)]
      });
    }
    const expectedDeleted = new Set(fixtures.filter(item => {
      const retentionClass = classifyAuditEvent(item.action, item.outcome);
      return retentionClass !== 'long_retained' && isAuditRetentionExpired(retentionClass, item.ts, AS_OF);
    }).map(item => item.id));
    assert.ok(expectedDeleted.size > 0);
    for (const item of fixtures) {
      if (classifyAuditEvent(item.action, item.outcome) === 'long_retained') assert.ok(!expectedDeleted.has(item.id));
    }

    const predicate = buildPhaseAPredicate({ asOf: AS_OF, firstParam: 2 });
    const matched = await catalog.pool.query({
      text: `SELECT id FROM ${SCHEMA}.audit_events_v2 WHERE starts_with(id, $1) AND ${predicate.text}`,
      values: [prefix, ...predicate.values]
    });
    const matchedIds = new Set(matched.rows.map(row => row.id));
    for (const item of fixtures) {
      assert.equal(matchedIds.has(item.id), expectedDeleted.has(item.id), `${item.action}/${item.outcome} @ ${item.ts}`);
    }

    const before = await snapshotSchemaTables(catalog.pool);
    const preview = await previewPhaseA({ pool: catalog.pool, asOf: AS_OF });
    const inventory = await countAuditRowsByPair({ pool: catalog.pool });
    assert.deepEqual(await snapshotSchemaTables(catalog.pool), before, 'preview and inventory must not change any table');
    assert.ok(preview.eligibleTotal >= expectedDeleted.size);
    assert.equal(preview.eligibleByClass.long_retained, 0);
    for (const [action, outcome] of UNKNOWN_PAIRS) {
      const pair = inventory.unknownPairs.find(item => item.action === action && item.outcome === outcome);
      assert.ok(pair, `${action}/${outcome} reported as unknown`);
      assert.equal(pair.retentionClass, 'long_retained');
    }

    let deleted = 0;
    for (let batch = 0; batch < 1000; batch += 1) {
      const result = await runPhaseADeleteBatch({ pool: catalog.pool, asOf: AS_OF, batchSize: 37 });
      assert.ok(result.deletedCount <= 37);
      assert.equal(result.deletedByClass.long_retained, 0);
      deleted += result.deletedCount;
      if (result.deletedCount === 0) break;
    }
    assert.ok(deleted >= expectedDeleted.size);
    const remaining = await catalog.pool.query({ text: `SELECT id FROM ${SCHEMA}.audit_events_v2 WHERE starts_with(id, $1)`, values: [prefix] });
    const remainingIds = new Set(remaining.rows.map(row => row.id));
    for (const item of fixtures) {
      assert.equal(remainingIds.has(item.id), !expectedDeleted.has(item.id), `${item.action}/${item.outcome} @ ${item.ts}`);
    }
    assert.equal((await runPhaseADeleteBatch({ pool: catalog.pool, asOf: AS_OF, batchSize: 37 })).deletedCount, 0, 'rerun is a no-op');
    await assert.rejects(() => runPhaseADeleteBatch({ pool: catalog.pool, table: 'raw_events_v2', asOf: AS_OF }), /audit_retention_table_not_allowed/);
  } finally {
    try { await catalog.pool.query({ text: `DELETE FROM ${SCHEMA}.audit_events_v2 WHERE starts_with(id, $1)`, values: [prefix] }); } catch { /* best effort */ }
    await catalog.close();
  }
});
