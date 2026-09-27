import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { PostgresCatalog } from '../src/fabric-store.mjs';
import { runCli } from './amf-audit-retention-gc-operator.mjs';

const connectionString = String(process.env.AMF_TEST_POSTGRES_URL || '').trim();
const enabled = connectionString && process.env.AMF_TEST_POSTGRES_ALLOW_MUTATION === 'true';
const SCHEMA = 'agent_memory_fabric';
const SSL_MODE = process.env.AMF_TEST_POSTGRES_SSL === 'disable' ? 'disable' : 'verify-full';
// Injected clock: only the 2000-era fixtures below are eligible, never rows other suites wrote.
const NOW = new Date('2020-06-01T00:00:00.000Z');
const BACKUP_VERIFIED_AT = '2020-05-31T23:00:00.000Z';

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

function probeDouble({ systemIdentifier, freeBytes = [50_000_000_000], fail = false }) {
  const calls = [];
  let dfCalls = 0;
  const runCommand = async argv => {
    calls.push(argv);
    if (fail) throw new Error('ssh unavailable');
    if (argv[4].includes("'psql")) return { stdout: `${systemIdentifier}\n` };
    const avail = freeBytes[Math.min(dfCalls, freeBytes.length - 1)];
    dfCalls += 1;
    return { stdout: `     Avail   1B-blocks\n${avail} 100000000000\n` };
  };
  return { runCommand, calls };
}

async function refusalCode(promise) {
  try { await promise; } catch (error) { return error.code; }
  throw new Error('expected a refusal but the call succeeded');
}

test('audit retention operator CLI against real PostgreSQL', { skip: !enabled }, async () => {
  const databaseName = decodeURIComponent(new URL(connectionString).pathname.replace(/^\//, ''));
  assert.match(databaseName, /(^|[-_])test($|[-_])/i, 'AMF_TEST_POSTGRES_URL must reference an isolated test database');
  const catalog = new PostgresCatalog({ connectionString, ssl: SSL_MODE === 'disable' ? false : { rejectUnauthorized: true } });
  const prefix = `audit-operator-${crypto.randomUUID()}-`;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-audit-operator-'));
  const logPath = path.join(dir, 'operator.jsonl');
  const logLines = () => (fs.existsSync(logPath) ? fs.readFileSync(logPath, 'utf8').trim().split('\n').filter(Boolean).map(line => JSON.parse(line)) : []);
  try {
    await catalog.ready();
    const identity = (await catalog.pool.query(`SELECT system_identifier::text AS id, current_database() AS db, current_setting('data_directory') AS dir FROM pg_control_system()`)).rows[0];
    const confirmTarget = `${identity.id}/${databaseName}`;
    const match = () => probeDouble({ systemIdentifier: identity.id });
    const cli = (args, runCommand = match().runCommand) => runCli(['node', 'cli', ...args, '--database-url', connectionString, '--ssl-mode', SSL_MODE], { runCommand, now: () => NOW });
    const probeArgs = ['--db-host-probe', 'pct', '--proxmox-host', 'pve-test', '--ctid', '999'];
    const applyArgs = (overrides = {}) => {
      const values = {
        '--approval': 'audit-bulk-delete', '--confirm-target': confirmTarget, '--backup-id': 'backup-test',
        '--backup-verified-at': BACKUP_VERIFIED_AT, '--operator-log': logPath, '--batch-size': '2', '--pause-ms': '0',
        '--probe-every': '2', '--max-batches': '1000', '--free-space-floor-bytes': '1000000000', ...overrides
      };
      return ['audit-phase-a', '--apply', '--i-know-this-is-live', '--json', ...probeArgs,
        ...Object.entries(values).filter(([, value]) => value !== null).flat()];
    };

    const expired = [];
    const kept = [];
    let sequence = 0;
    async function insert(action, outcome, ts, bucket) {
      const id = `${prefix}${++sequence}`;
      bucket.push(id);
      await catalog.pool.query({ text: `INSERT INTO ${SCHEMA}.audit_events_v2(id,ts,actor_tag,action,outcome,details_json) VALUES ($1,$2,'integration-actor',$3,$4,'{}'::jsonb)`, values: [id, ts, action, outcome] });
    }
    for (let i = 0; i < 4; i += 1) await insert('memory_status', 'allowed', '2000-01-01T00:00:00.000Z', expired);
    for (let i = 0; i < 3; i += 1) await insert('raw_ingest_decrypt_intent', 'authorized', '2000-01-01T00:00:00.000Z', expired);
    await insert('session_get', 'allowed', '2000-01-01T00:00:00.000Z', expired);
    await insert('session_get', 'allowed', '2020-05-30T00:00:00.000Z', kept);
    await insert('memory_propose', 'queued', '2000-01-01T00:00:00.000Z', kept);
    await insert('curation_decision_receipt', 'recorded', '2000-01-01T00:00:00.000Z', kept);
    await insert('memory_status', 'throttled', '2000-01-01T00:00:00.000Z', kept);
    await insert('not_a_known_action', 'allowed', '2000-01-01T00:00:00.000Z', kept);
    const survivors = async () => new Set((await catalog.pool.query({ text: `SELECT id FROM ${SCHEMA}.audit_events_v2 WHERE starts_with(id, $1)`, values: [prefix] })).rows.map(row => row.id));

    const before = await snapshotSchemaTables(catalog.pool);
    const inventory = await cli(['inventory', '--json']);
    assert.equal(inventory.result.target.confirmTarget, confirmTarget);
    assert.equal(inventory.result.target.dataDirectory, identity.dir);
    assert.equal(inventory.result.freeSpace, 'unknown');
    assert.ok(inventory.result.table.unknownPairs.some(pair => pair.action === 'not_a_known_action'));
    const preview = await cli(['audit-phase-a', '--json', ...probeArgs]);
    assert.equal(preview.result.dryRun, true);
    assert.equal(preview.result.freeSpace.freeBytes, 50_000_000_000);
    assert.ok(preview.result.eligibleTotal >= expired.length);
    assert.equal(preview.result.eligibleByClass.long_retained, 0);
    assert.deepEqual(await snapshotSchemaTables(catalog.pool), before, 'inventory and preview leave every table unchanged');

    const refusals = [
      [applyArgs({ '--approval': null }), 'operator_approval_missing_or_wrong'],
      [applyArgs({ '--approval': 'raw-gc-live' }), 'operator_approval_missing_or_wrong'],
      [applyArgs({ '--confirm-target': `127.0.0.1:5432/${databaseName}` }), 'operator_target_confirmation_mismatch'],
      [applyArgs({ '--backup-verified-at': '2020-05-01T00:00:00.000Z' }), 'operator_backup_attestation_stale'],
      [applyArgs().filter(arg => !probeArgs.includes(arg)), 'operator_db_host_probe_required'],
      [applyArgs(), 'operator_db_host_identity_mismatch', probeDouble({ systemIdentifier: '1' }).runCommand],
      [applyArgs(), 'operator_db_host_probe_failed', probeDouble({ systemIdentifier: identity.id, fail: true }).runCommand],
      [applyArgs({ '--free-space-floor-bytes': '60000000000' }), 'operator_free_space_floor_breached']
    ];
    for (const [args, code, runCommand] of refusals) assert.equal(await refusalCode(cli(args, runCommand)), code, code);
    assert.equal(await refusalCode(cli(applyArgs({ '--operator-log': null }))), 'operator_log_required');
    assert.equal(await refusalCode(cli(['audit-phase-a', '--table', 'raw_events_v2'])), 'audit_retention_table_not_allowed');
    assert.deepEqual(await snapshotSchemaTables(catalog.pool), before, 'no refused attempt changed any table');
    assert.deepEqual(logLines().map(line => [line.outcome, line.error]), refusals.map(([, code]) => ['refused', code]));
    assert.ok(logLines().every(line => line.target.systemIdentifier === identity.id && /attestation/.test(line.attestation)));

    const dropping = probeDouble({ systemIdentifier: identity.id, freeBytes: [50_000_000_000, 40_000_000_000] });
    assert.equal(await refusalCode(cli(applyArgs({ '--max-free-space-drop-bytes': '1000000000' }), dropping.runCommand)), 'operator_free_space_dropped');
    const dropped = logLines().at(-1);
    assert.equal(dropped.outcome, 'stopped_on_error');
    assert.equal(dropped.stopReason, 'free_space_dropped');
    assert.equal(dropped.batches.length, 2, 'stopped at the first re-probe after two batches');
    assert.equal(dropped.totalDeleted, 4);

    const applied = await cli(applyArgs({ '--vacuum-between-groups': null }).concat('--vacuum-between-groups'));
    assert.equal(applied.result.dryRun, false);
    assert.equal(applied.result.stopReason, 'drained');
    assert.match(applied.result.attestation, /cannot verify/);
    assert.equal(applied.result.target.confirmTarget, confirmTarget);
    const remaining = await survivors();
    for (const id of expired) assert.ok(!remaining.has(id), `${id} deleted`);
    for (const id of kept) assert.ok(remaining.has(id), `${id} kept`);
    const completed = logLines().at(-1);
    assert.equal(completed.outcome, 'completed');
    assert.equal(completed.checkpoint, 'audit-bulk-delete');
    assert.equal(completed.backup.id, 'backup-test');
    assert.ok(completed.batches.every(batch => batch.deletedByClass.long_retained === 0));

    const rerun = await cli(applyArgs());
    assert.equal(rerun.result.totalDeleted, 0);
    assert.equal(rerun.result.stopReason, 'drained');
    assert.equal(logLines().length, refusals.length + 3);
  } finally {
    try { await catalog.pool.query({ text: `DELETE FROM ${SCHEMA}.audit_events_v2 WHERE starts_with(id, $1)`, values: [prefix] }); } catch { /* best effort */ }
    await catalog.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
