import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import BetterSqlite3 from 'better-sqlite3';
import { createConversationSessionRuntimeFromEnv } from '../src/conversation-session-runtime.mjs';
import { deriveM4V3ConversationIdFromLegacySessionId, deriveM4V3EventIdFromLegacyEventId } from '../src/migration/m4-v2-conversation-projector.mjs';

function temp() { return fs.mkdtempSync(path.join(os.tmpdir(), 'amf-runtime-')); }
const meta = id => ({ id, runtime: 'legacy', firstOccurredAt: '2026-01-01T00:00:00Z', lastOccurredAt: '2026-01-01T00:00:00Z', eventCount: 1, conversationKind: 'session', contextTags: { conversation: ['tag'] } });
function setup() {
  const root = temp(); const key = path.join(root, 'cursor.key'); fs.writeFileSync(key, `${Buffer.alloc(32, 9).toString('base64')}\n`, { mode: 0o600 });
  const archive = path.join(root, 'archive.sqlite'); const db = new BetterSqlite3(archive); db.exec('CREATE TABLE conversation_archive_events_v1 (event_id TEXT, conversation_id TEXT, source_instance_id TEXT, state TEXT, source_occurred_at TEXT, source_time_key TEXT, source_sequence INTEGER, event_json TEXT, expired INTEGER)'); db.close();
  return { root, env: { AMF_CONVERSATION_READER_MODE: 'active', AMF_CONVERSATION_ARCHIVE_SQLITE_PATH: 'archive.sqlite', AMF_CONVERSATION_READER_CURSOR_KEY_PATH: 'cursor.key', AMF_CONVERSATION_READER_SCAN_LIMIT: '2' } };
}
test('disabled is zero-touch and content-free', async () => {
  const hostile = new Proxy({}, { get(_target, name) { if (name === 'AMF_CONVERSATION_READER_MODE') return 'disabled'; throw new Error('touched'); } });
  const runtime = await createConversationSessionRuntimeFromEnv({ env: hostile, rootPath: '/no-touch' });
  assert.equal(runtime.reader, null); assert.deepEqual(runtime.status(), { mode: 'disabled', pending: 0, compared: 0, matched: 0, mismatched: 0, unavailable: 0, inconclusive: 0, skipped: 0 });
});
test('validates config fail-closed without plaintext errors', async () => {
  await assert.rejects(() => createConversationSessionRuntimeFromEnv({ env: { AMF_CONVERSATION_READER_MODE: 'active' }, rootPath: temp() }), /conversation_session_runtime_config_invalid/);
});
test('rejects linked cursor keys and detects an archive path swap during open', async () => {
  const linked = setup(); fs.linkSync(path.join(linked.root, 'cursor.key'), path.join(linked.root, 'cursor-copy.key'));
  await assert.rejects(() => createConversationSessionRuntimeFromEnv({ env: linked.env, rootPath: linked.root }), /conversation_session_runtime_config_invalid/);
  const swapped = setup();
  class SwappingDb {
    constructor(filename) {
      fs.renameSync(filename, `${filename}.original`);
      fs.writeFileSync(filename, 'substituted');
    }
  }
  await assert.rejects(() => createConversationSessionRuntimeFromEnv({ env: swapped.env, rootPath: swapped.root, dependencies: { BetterSqlite3: SwappingDb } }), /conversation_session_runtime_unavailable/);
});
test('SQLite opens the anchored descriptor when the configured path is swapped and restored', async () => {
  const fixed = setup(); const archive = path.join(fixed.root, 'archive.sqlite');
  class SwapAndOpenDb {
    constructor(filename, options) {
      assert.match(filename, /^\/proc\/self\/fd\/\d+$/);
      const original = `${archive}.original`; fs.renameSync(archive, original);
      const substitute = new BetterSqlite3(archive); substitute.exec('CREATE TABLE substituted (value TEXT)'); substitute.close();
      const opened = new BetterSqlite3(filename, options);
      fs.unlinkSync(archive); fs.renameSync(original, archive);
      return opened;
    }
  }
  const runtime = await createConversationSessionRuntimeFromEnv({ env: fixed.env, rootPath: fixed.root, dependencies: { BetterSqlite3: SwapAndOpenDb } });
  await runtime.ready(); await runtime.close();
});
test('rejects symlinked and oversized PostgreSQL CA files before pool construction', async () => {
  const root = temp(); const key = path.join(root, 'cursor.key'); fs.writeFileSync(key, `${Buffer.alloc(32, 6).toString('base64')}\n`, { mode: 0o600 });
  const target = path.join(root, 'ca-target.pem'); fs.writeFileSync(target, 'certificate'); fs.symlinkSync(target, path.join(root, 'ca.pem'));
  const base = { AMF_CONVERSATION_READER_MODE: 'active', AMF_CONVERSATION_ARCHIVE_POSTGRES_URL: 'postgresql://reader@example.invalid/archive', AMF_CONVERSATION_READER_CURSOR_KEY_PATH: 'cursor.key', AMF_CONVERSATION_ARCHIVE_POSTGRES_CA_PATH: 'ca.pem' };
  await assert.rejects(() => createConversationSessionRuntimeFromEnv({ rootPath: root, env: base, dependencies: { Pool: class {} } }), /conversation_session_runtime_config_invalid/);
  fs.unlinkSync(path.join(root, 'ca.pem')); fs.writeFileSync(path.join(root, 'ca.pem'), Buffer.alloc(1_048_577));
  await assert.rejects(() => createConversationSessionRuntimeFromEnv({ rootPath: root, env: base, dependencies: { Pool: class {} } }), /conversation_session_runtime_config_invalid/);
});
test('PostgreSQL composition enforces read-only sessions and bounded pool settings', async () => {
  const root = temp(); const key = path.join(root, 'cursor.key'); fs.writeFileSync(key, `${Buffer.alloc(32, 7).toString('base64')}\n`, { mode: 0o600 });
  let poolOptions; let ended = false;
  class Pool { constructor(options) { poolOptions = options; } async query() { return { rows: [] }; } async end() { ended = true; } }
  class View { constructor({ pool }) { this.pool = pool; this.configured = true; this.kind = 'test-v3'; } }
  const runtime = await createConversationSessionRuntimeFromEnv({ rootPath: root, env: {
    AMF_CONVERSATION_READER_MODE: 'active', AMF_CONVERSATION_ARCHIVE_POSTGRES_URL: 'postgresql://reader@example.invalid/archive',
    AMF_CONVERSATION_READER_CURSOR_KEY_PATH: 'cursor.key'
  }, dependencies: { Pool, PostgresConversationSessionView: View } });
  assert.equal(poolOptions.options, '-c default_transaction_read_only=on');
  assert.deepEqual({ max: poolOptions.max, statement: poolOptions.statement_timeout, query: poolOptions.query_timeout }, { max: 4, statement: 5_000, query: 5_000 });
  await runtime.ready(); await runtime.close(); assert.equal(ended, true);
});
test('PostgreSQL connection URLs cannot override TLS or read-only settings', async () => {
  const root = temp(); fs.writeFileSync(path.join(root, 'cursor.key'), `${Buffer.alloc(32, 5).toString('base64')}\n`, { mode: 0o600 });
  const base = { AMF_CONVERSATION_READER_MODE: 'active', AMF_CONVERSATION_READER_CURSOR_KEY_PATH: 'cursor.key' };
  for (const suffix of ['?sslmode=disable', '?options=-c%20default_transaction_read_only%3Doff', '#fragment']) {
    await assert.rejects(() => createConversationSessionRuntimeFromEnv({ rootPath: root, env: { ...base, AMF_CONVERSATION_ARCHIVE_POSTGRES_URL: `postgresql://reader@example.invalid/archive${suffix}` } }), /conversation_session_runtime_config_invalid/);
  }
});
test('active SQLite opens readonly, proves reachability, and closes', async () => {
  const { root, env } = setup(); const runtime = await createConversationSessionRuntimeFromEnv({ env, rootPath: root });
  await runtime.ready(); assert.equal(runtime.reader.runtimeStatus().mode, 'active'); assert.equal(runtime.reader.db.readonly, true);
  assert.deepEqual(await runtime.reader.search({ context: { contextTags: { conversation: [`hmac-sha256:test:${'a'.repeat(64)}`] } }, limit: 2 }), { items: [], total: 0, nextCursor: null });
  await runtime.close(); await runtime.close();
});
test('shadow serves legacy and records match, mismatch, unavailable, and bounded skips', async () => {
  const { root, env } = setup(); env.AMF_CONVERSATION_READER_MODE = 'shadow';
  const id = `ses_${'a'.repeat(64)}`; let calls = 0; const legacy = { async get(args) { calls += 1; return meta(args.id); }, async transcript(args) { return { id: args.id, view: 'redacted', items: [], nextCursor: null }; }, async search() { return { items: [], nextCursor: null }; } };
  const V3 = class { constructor() {} async get() { return meta(`ccon_${'f'.repeat(64)}`); } async transcript(args) { return { id: args.id, view: 'redacted', items: [], nextCursor: null }; } async search() { return { items: [], nextCursor: null }; } };
  const runtime = await createConversationSessionRuntimeFromEnv({ env, rootPath: root, legacyReader: legacy, dependencies: { SqliteConversationSessionView: V3 } });
  assert.equal((await runtime.reader.get({ id })).id, id); await new Promise(resolve => setImmediate(resolve));
  const status = runtime.status(); assert.equal(calls, 1); assert.equal(status.compared, 1); assert.equal(status.mismatched, 1); assert.deepEqual(runtime.reader.runtimeStatus(), status);
  await runtime.reader.search({}); await new Promise(resolve => setImmediate(resolve)); assert.equal(runtime.status().compared, 2); await runtime.close();
});
test('shadow counts matching, unavailable, and bounded comparisons without exposing values', async () => {
  const { root, env } = setup(); env.AMF_CONVERSATION_READER_MODE = 'shadow';
  const id = `ses_${'b'.repeat(64)}`; const mapped = deriveM4V3ConversationIdFromLegacySessionId(id); const legacy = { async get() { return meta(id); }, async transcript() { return { id, view: 'redacted', items: [], nextCursor: null }; }, async search() { return { items: [], nextCursor: null }; } };
  const V3 = class { async get() { return meta(mapped); } async transcript() { return { id: mapped, view: 'redacted', items: [], nextCursor: null }; } async search() { return { items: [], nextCursor: null }; } };
  const runtime = await createConversationSessionRuntimeFromEnv({ env, rootPath: root, legacyReader: legacy, dependencies: { SqliteConversationSessionView: V3 } });
  await runtime.reader.get({ id }); await new Promise(resolve => setImmediate(resolve)); assert.equal(runtime.status().matched, 1);
  await runtime.close();
  // A closed runtime does not schedule a comparison and records only content-free counters.
  await runtime.reader.get({ id }); assert.ok(runtime.status().skipped >= 1);
  assert.doesNotMatch(JSON.stringify(runtime.status()), /ses_|ccon_|plaintext/i);
});
test('shadow rejects legacy identifiers returned by the v3 side as a mismatch', async () => {
  const { root, env } = setup(); env.AMF_CONVERSATION_READER_MODE = 'shadow'; const id = `ses_${'9'.repeat(64)}`;
  const legacy = { async get() { return meta(id); }, async transcript() { return { id, view: 'redacted', items: [], nextCursor: null }; }, async search() { return { items: [], nextCursor: null }; } };
  const V3 = class { async get() { return meta(id); } async transcript() { return { id, view: 'redacted', items: [], nextCursor: null }; } async search() { return { items: [], nextCursor: null }; } };
  const runtime = await createConversationSessionRuntimeFromEnv({ env, rootPath: root, legacyReader: legacy, dependencies: { SqliteConversationSessionView: V3 } });
  await runtime.reader.get({ id }); await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual({ compared: runtime.status().compared, mismatched: runtime.status().mismatched }, { compared: 1, mismatched: 1 });
  await runtime.close();
});
test('shadow bounds pending work and counts unavailable v3 comparisons', async () => {
  const { root, env } = setup(); env.AMF_CONVERSATION_READER_MODE = 'shadow'; const id = `ses_${'c'.repeat(64)}`;
  const legacy = { async get(args) { return meta(args.id); }, async transcript() { return { nextCursor: null }; }, async search() { return { items: [], nextCursor: null }; } }; let release; const hold = new Promise(resolve => { release = resolve; });
  const V3 = class { async get() { await hold; throw new Error('private failure'); } async transcript() { return { nextCursor: null }; } async search() { return { items: [], nextCursor: null }; } };
  const runtime = await createConversationSessionRuntimeFromEnv({ env, rootPath: root, legacyReader: legacy, dependencies: { SqliteConversationSessionView: V3 } });
  await Promise.all(Array.from({ length: 5 }, () => runtime.reader.get({ id }))); await new Promise(resolve => setImmediate(resolve));
  assert.equal(runtime.status().pending, 4); assert.equal(runtime.status().skipped, 1); release(); await new Promise(resolve => setImmediate(resolve));
  assert.equal(runtime.status().unavailable, 4); await runtime.close();
});

test('shadow maps transcript events, compares complete search sets, and marks partial pages inconclusive', async () => {
  const { root, env } = setup(); env.AMF_CONVERSATION_READER_MODE = 'shadow';
  const first = `ses_${'d'.repeat(64)}`; const second = `ses_${'e'.repeat(64)}`; const legacyEvent = `evt_${'f'.repeat(64)}`;
  const mappedFirst = deriveM4V3ConversationIdFromLegacySessionId(first); const mappedSecond = deriveM4V3ConversationIdFromLegacySessionId(second);
  const content = { redacted: true, contentType: 'text', parts: 1, text: 'synthetic visible text' };
  let paged = false;
  const legacy = {
    async get() { return meta(first); },
    async transcript() { return { id: first, view: 'redacted', items: [{ eventId: legacyEvent, occurredAt: '2026-01-01T00:00:00Z', role: 'user', content }], nextCursor: paged ? 'legacy-cursor' : null }; },
    async search() { return { items: [meta(second), meta(first)], nextCursor: paged ? 'legacy-cursor' : null }; },
  };
  const V3 = class {
    async get() { return meta(mappedFirst); }
    async transcript() { return { id: mappedFirst, view: 'redacted', items: [{ eventId: deriveM4V3EventIdFromLegacyEventId(legacyEvent), occurredAt: '2026-01-01T00:00:00Z', role: 'user', content }], nextCursor: paged ? 'v3-cursor' : null }; }
    async search() { return { items: [meta(mappedFirst), meta(mappedSecond)], nextCursor: paged ? 'v3-cursor' : null }; }
  };
  const runtime = await createConversationSessionRuntimeFromEnv({ env, rootPath: root, legacyReader: legacy, dependencies: { SqliteConversationSessionView: V3 } });
  await runtime.reader.transcript({ id: first }); await runtime.reader.search({}); await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual({ compared: runtime.status().compared, matched: runtime.status().matched }, { compared: 2, matched: 2 });
  paged = true; await runtime.reader.transcript({ id: first }); await runtime.reader.search({}); await new Promise(resolve => setImmediate(resolve));
  assert.equal(runtime.status().inconclusive, 2); assert.equal(runtime.status().compared, 2);
  await runtime.close();
});

if (process.env.AMF_ARCHIVE_POSTGRES_TEST_URL) {
  test('PostgreSQL runtime rejects writes at the session boundary', async () => {
    const root = temp(); fs.writeFileSync(path.join(root, 'cursor.key'), `${Buffer.alloc(32, 8).toString('base64')}\n`, { mode: 0o600 });
    const runtime = await createConversationSessionRuntimeFromEnv({ rootPath: root, env: {
      AMF_CONVERSATION_READER_MODE: 'active', AMF_CONVERSATION_ARCHIVE_POSTGRES_URL: process.env.AMF_ARCHIVE_POSTGRES_TEST_URL,
      AMF_CONVERSATION_READER_CURSOR_KEY_PATH: 'cursor.key', AMF_CONVERSATION_ARCHIVE_POSTGRES_SSL_MODE: 'disable'
    } });
    const client = await runtime.reader.pool.connect();
    try {
      await client.query('BEGIN');
      await assert.rejects(client.query('CREATE TABLE amf_conversation_reader_write_probe (id integer)'), error => error?.code === '25006');
    } finally {
      await client.query('ROLLBACK').catch(() => undefined); client.release(); await runtime.close();
    }
  });
}
