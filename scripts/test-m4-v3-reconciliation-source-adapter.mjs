import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import test from 'node:test';

import Database from 'better-sqlite3';

import { createM4V3ReconciliationSource } from '../src/operator/m4-v3-reconciliation-source-adapter.mjs';
import { planM4ReconciliationCollection } from '../src/operator/m4-reconciliation-collector-operator.mjs';
import { runM4ReconciliationCollection } from '../src/operator/m4-reconciliation-collector-operator.mjs';
import { runM4ReconciliationCollectCli } from './amf-m4-reconciliation-collect.mjs';

const digest = char => `sha256:${char.repeat(64)}`;
const row = { event_id: 'cevt_adapter0001', payload_digest: digest('a'), logical_digest: digest('b'),
  source_occurred_at: '2026-07-22T00:00:00Z', event_json: JSON.stringify({ occurredAt: '2026-07-22T00:00:01Z' }), state: 'active' };
function sourceConfig(databasePath) { return { schema: 'amf.m4-v3-reconciliation-source-adapter/v1', archive: 'v3',
  driver: 'sqlite', databasePath, pageSize: 2 }; }
function input(value) { return { archive: 'v3', config: {}, sourceConfig: value }; }
function temporary(t) { const root = fs.mkdtempSync(path.join(os.tmpdir(), 'm4-v3-adapter-')); fs.chmodSync(root, 0o700); t.after(() => fs.rmSync(root, { recursive: true, force: true })); return root; }
function databaseFile(t) {
  const target = path.join(temporary(t), 'source.db'); const db = new Database(target);
  db.exec('CREATE TABLE conversation_archive_events_v1 (event_id TEXT, state TEXT, logical_digest TEXT, payload_digest TEXT, source_occurred_at TEXT, event_json TEXT)');
  db.prepare('INSERT INTO conversation_archive_events_v1 VALUES (@event_id,@state,@logical_digest,@payload_digest,@source_occurred_at,@event_json)').run(row); db.close(); fs.chmodSync(target, 0o600); return target;
}

test('SQLite source opens a real owner-only database read-only and closes once', async t => {
  const target = databaseFile(t); fs.truncateSync(target, 68 * 1024 * 1024);
  const source = createM4V3ReconciliationSource(input(sourceConfig(target)));
  const revision = await source.revisionSource(); const events = [];
  for await (const event of source.events) events.push(event);
  await source.close(); await source.close();
  assert.equal(revision.state, 'complete'); assert.deepEqual(events.map(event => event.eventId), [row.event_id]);
});

test('SQLite fails closed when the validated pathname is replaced during open', t => {
  const target = databaseFile(t); const replacement = databaseFile(t);
  const replacementDb = new Database(replacement);
  replacementDb.prepare('UPDATE conversation_archive_events_v1 SET event_id=?').run('cevt_replacement0001');
  replacementDb.close();
  class ReplacingDatabase {
    constructor(filename, options) {
      fs.renameSync(replacement, target);
      return new Database(filename, options);
    }
  }
  assert.throws(() => createM4V3ReconciliationSource(input(sourceConfig(target)), {
    Database: ReplacingDatabase,
  }), { code: 'm4_v3_reconciliation_source_adapter_invalid' });
});

test('SQLite accepts private WAL state and rejects a writable database directory', async t => {
  const target = path.join(temporary(t), 'wal-source.db'); const writer = new Database(target);
  writer.pragma('journal_mode = WAL'); writer.pragma('wal_autocheckpoint = 0');
  writer.exec('CREATE TABLE conversation_archive_events_v1 (event_id TEXT, state TEXT, logical_digest TEXT, payload_digest TEXT, source_occurred_at TEXT, event_json TEXT)');
  writer.prepare('INSERT INTO conversation_archive_events_v1 VALUES (@event_id,@state,@logical_digest,@payload_digest,@source_occurred_at,@event_json)').run(row);
  fs.chmodSync(target, 0o600);
  const source = createM4V3ReconciliationSource(input(sourceConfig(target)));
  await source.revisionSource(); const events = [];
  for await (const event of source.events) events.push(event);
  await source.close(); assert.deepEqual(events.map(event => event.eventId), [row.event_id]); writer.close();
  fs.chmodSync(path.dirname(target), 0o755);
  assert.throws(() => createM4V3ReconciliationSource(input(sourceConfig(target))), {
    code: 'm4_v3_reconciliation_source_adapter_invalid',
  });
});

test('SQLite rejects unsafe, missing, and symlink database paths without exposing paths', t => {
  const target = databaseFile(t); fs.chmodSync(target, 0o644);
  assert.throws(() => createM4V3ReconciliationSource(input(sourceConfig(target))), { code: 'm4_v3_reconciliation_source_adapter_invalid' });
  const missing = path.join(temporary(t), 'missing.db');
  assert.throws(() => createM4V3ReconciliationSource(input(sourceConfig(missing))), { code: 'm4_v3_reconciliation_source_adapter_invalid' });
  const linked = path.join(temporary(t), 'linked.db'); fs.symlinkSync(target, linked);
  assert.throws(() => createM4V3ReconciliationSource(input(sourceConfig(linked))), { code: 'm4_v3_reconciliation_source_adapter_invalid' });
});

test('plan binds source configuration, detects its drift, and never opens the source factory', async t => {
  const root = temporary(t); let opens = 0; const write = (name, value) => { const target = path.join(root, name); fs.writeFileSync(target, JSON.stringify(value), { mode: 0o600 }); return target; };
  const checkpoint = { id: 'checkpoint-one', digest: digest('c') }; const key = id => ({ schema: 'amf.migration-signing-key/v1', keyId: id, key: Buffer.alloc(32, id).toString('base64') });
  const config = { schema: 'amf.m4-reconciliation-collector-operator/v1', artifactRoot: root, bundleId: 'adapter-bundle', archive: 'v3', snapshotId: 'adapter-snapshot', revisionManifestId: 'adapter-revision', revision: 1,
    completionPath: write('completion.json', { state: 'complete', checkpoint }), completionKeyPath: write('completion-key.json', key('completion-key')), revisionKeyPath: write('revision-key.json', key('revision-key')), snapshotKeyPath: write('snapshot-key.json', key('snapshot-key')),
    staticEvidencePath: write('evidence.json', { pausedInterval: { start: checkpoint, end: checkpoint }, replayQueues: { pendingOutbox: checkpoint, acknowledgements: checkpoint, deadLetters: checkpoint }, sourceCheckpoints: { collectorCursor: checkpoint, sourceCheckpoint: checkpoint, nativeTranscriptAuthority: checkpoint } }),
    sourceConfigPath: write('source.json', sourceConfig(path.join(root, 'not-opened.db'))), revisionValiditySeconds: 60, maxEvents: 1 };
  const configPath = write('config.json', config);
  const plan = await planM4ReconciliationCollection({ configPath }, { createSource: async () => { opens += 1; throw new Error('must not open'); }, verifyNativeCompletion: value => value });
  assert.equal(plan.state, 'planned'); assert.equal(opens, 0);
  fs.writeFileSync(config.sourceConfigPath, JSON.stringify({ ...sourceConfig(path.join(root, 'not-opened.db')), pageSize: 3 }), { mode: 0o600 });
  await assert.rejects(() => runM4ReconciliationCollection({ configPath, confirmedPlanDigest: plan.confirmationDigest }, { createSource: async () => { opens += 1; throw new Error('must not open'); }, verifyNativeCompletion: value => value }), { code: 'm4_reconciliation_collector_operator_confirmation_invalid' });
  assert.equal(opens, 0);
});

test('PostgreSQL uses a bounded Pool configuration, SSL modes, and releases/ends once on failure', async t => {
  const root = temporary(t); const caPath = path.join(root, 'ca.pem'); fs.writeFileSync(caPath, 'synthetic-ca', { mode: 0o600 });
  const columns = ['event_id', 'state', 'logical_digest', 'payload_digest', 'source_occurred_at', 'event_json']; let released = 0; let ended = 0; let options;
  class Pool { constructor(value) { options = value; } async connect() { return { async query(sql) { if (sql.startsWith('SELECT column_name')) return { rows: columns.map(column_name => ({ column_name })) }; if (sql.startsWith('SELECT event_id')) return { rows: [] }; return { rows: [] }; }, release() { released += 1; } }; } async end() { ended += 1; } }
  const config = { schema: 'amf.m4-v3-reconciliation-source-adapter/v1', archive: 'v3', driver: 'postgres', host: 'synthetic', port: 5432, database: 'synthetic', user: 'synthetic', password: 'synthetic', sslMode: 'verify-full', caPath, pageSize: 1, connectionTimeoutMillis: 100, idleTimeoutMillis: 100, queryTimeoutMillis: 100, statementTimeoutMillis: 100 };
  const source = createM4V3ReconciliationSource(input(config), { Pool }); await source.revisionSource(); await source.close(); await source.close();
  assert.equal(options.max, 1); assert.equal(options.ssl.rejectUnauthorized, true); assert.equal(options.query_timeout, 100); assert.equal(options.statement_timeout, 100); assert.equal(released, 1); assert.equal(ended, 1);
  const failing = createM4V3ReconciliationSource(input(config), { Pool: class extends Pool { async connect() { throw new Error('private connection detail'); } } });
  await assert.rejects(() => failing.revisionSource(), { code: 'm4_reconciliation_collector_source_invalid' }); await assert.rejects(() => failing.close(), { code: 'm4_v3_reconciliation_source_adapter_invalid' });
  assert.equal(ended, 2); assert.throws(() => createM4V3ReconciliationSource({ archive: 'legacy-v2', config: {}, sourceConfig: config }), { code: 'm4_v3_reconciliation_source_adapter_legacy_unsupported' });
});

test('CLI arguments are exact and public output redacts invalid private values', async () => {
  await assert.rejects(() => runM4ReconciliationCollectCli(['node', 'cli', 'plan', '--config', 'relative']), { code: 'm4_reconciliation_collect_cli_argument_invalid' });
  await assert.rejects(() => runM4ReconciliationCollectCli(['node', 'cli', 'run', '--config', '/synthetic/config', '--confirmed-plan-digest', 'bad']), { code: 'm4_reconciliation_collect_cli_argument_invalid' });
  assert.throws(() => execFileSync(process.execPath, ['scripts/amf-m4-reconciliation-collect.mjs', 'plan', '--config', 'relative'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }), error => {
    assert.equal(error.status, 78); assert.equal(error.stdout, ''); assert.equal(error.stderr.includes('relative'), false); return true;
  });
});
