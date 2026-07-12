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
  createFabricStoreFromEnv
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
    this.auditEvents = new Map();
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
  for (const table of ['schema_migrations', 'raw_objects_v2', 'fabric_proposals', 'identity_records', 'ingest_cursors', 'audit_events_v2', 'retention_tombstones']) {
    assert.match(ddl, new RegExp(`${POSTGRES_SCHEMA}\\.${table}`));
  }
  assert.match(ddl, /UNIQUE\(owner_tag, idempotency_tag\)/);
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

    let poolConfig;
    const pool = new FakePool();
    const store = createFabricStoreFromEnv({
      rootPath: root,
      env: {
        ...base, AMF_CATALOG_DATABASE_URL: 'postgres://db/amf_test', AMF_CATALOG_SSL_MODE: 'require', AMF_CATALOG_POOL_MAX: '7',
        AMF_CATALOG_CONNECT_TIMEOUT_MS: '4000', AMF_CATALOG_QUERY_TIMEOUT_MS: '9000', AMF_CATALOG_STATEMENT_TIMEOUT_MS: '8000'
      },
      postgresPoolFactory: (config) => { poolConfig = config; return pool; }
    });
    assert.equal(store.status().backend, 'postgres');
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
