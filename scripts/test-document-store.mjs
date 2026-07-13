import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

import { MemoryDocumentStore, PostgresDocumentStore, SqliteDocumentStore } from '../src/document-store.mjs';

const fixture = JSON.parse(fs.readFileSync(new URL('./fixtures/contracts/obsidian-document-lifecycle.json', import.meta.url), 'utf8'));

class FakeDocumentPool {
  constructor() { this.revisions = new Map(); this.idempotency = new Map(); this.heads = new Map(); this.queries = []; }
  async connect() { return { query: (text, values) => this.query(text, values), release() {} }; }
  async query(text, values = []) {
    this.queries.push({ text, values });
    const sql = text.replace(/\s+/g, ' ').trim();
    if (sql.startsWith('CREATE SCHEMA') || ['BEGIN', 'COMMIT', 'ROLLBACK'].includes(sql) || sql.startsWith('SELECT pg_advisory')) return { rows: [] };
    if (sql.includes('WHERE idempotency_key=$1')) return { rows: [this.idempotency.get(values[0])].filter(Boolean) };
    if (sql.includes('WHERE h.document_id=$1 FOR UPDATE') || (sql.includes('WHERE h.document_id=$1') && !sql.includes('FOR UPDATE'))) {
      const head = this.heads.get(values[0]); return { rows: [head && this.revisions.get(`${values[0]}\0${head.revision}`)].filter(Boolean) };
    }
    if (sql.startsWith('SELECT * FROM agent_memory_fabric.document_revisions_v1 WHERE document_id=$1')) return { rows: [this.revisions.get(`${values[0]}\0${values[1]}`)].filter(Boolean) };
    if (sql.startsWith('INSERT INTO agent_memory_fabric.document_revisions_v1')) {
      const row = {
        document_id: values[0], vault_id: values[1], revision: values[2], path: values[3], previous_path: values[4], content_digest: values[5],
        media_type: values[6], source_modified_at: values[7], tombstone: values[8], extraction_json: JSON.parse(values[9]), provenance_json: JSON.parse(values[10]),
        text_content: values[11], idempotency_key: values[12], request_digest: values[13]
      };
      this.revisions.set(`${row.document_id}\0${row.revision}`, row); this.idempotency.set(row.idempotency_key, row); return { rows: [] };
    }
    if (sql.startsWith('INSERT INTO agent_memory_fabric.document_heads_v1')) {
      this.heads.set(values[0], { documentId: values[0], vaultId: values[1], revision: values[2], path: values[3], tombstone: values[4] }); return { rows: [] };
    }
    if (sql.includes('h.tombstone=false AND h.vault_id=ANY')) {
      return { rows: [...this.heads.values()].filter(head => !head.tombstone && values[0].includes(head.vaultId)).map(head => this.revisions.get(`${head.documentId}\0${head.revision}`)) };
    }
    if (sql.startsWith('SELECT count(*)::bigint')) return { rows: [{ count: String(this.heads.size) }] };
    throw new Error(`unexpected query: ${sql}`);
  }
  async end() {}
}

for (const [name, createStore] of [['memory', () => new MemoryDocumentStore()], ['sqlite', () => new SqliteDocumentStore()]]) {
  test(`${name} document store conforms for create, replay, rename, search, tombstone, and history`, async () => {
    const store = createStore();
    try {
      const created = await store.upsert(fixture.create);
      assert.equal(created.duplicate, false);
      const replay = await store.upsert(fixture.create);
      assert.equal(replay.duplicate, true);
      assert.equal(replay.document.documentId, created.document.documentId);
      assert.equal((await store.read({ documentId: created.document.documentId })).path, fixture.create.document.path);

      const renamed = await store.upsert(fixture.rename);
      assert.equal(renamed.document.documentId, created.document.documentId);
      assert.equal((await store.search({ query: 'memory fabric', vaultIds: ['vault-personal'], limit: 20 })).length, 1);
      assert.equal((await store.read({ documentId: created.document.documentId, revision: 1 })).path, fixture.create.document.path);

      const deleted = await store.delete(fixture.delete);
      assert.equal(deleted.document.tombstone, true);
      assert.equal((await store.search({ query: 'memory', vaultIds: ['vault-personal'], limit: 20 })).length, 0);
      assert.equal((await store.read({ documentId: created.document.documentId })).revision, 3);
      assert.equal((await store.health()).documents, 1);
    } finally { await store.close?.(); }
  });
}

test('document store rejects stale revisions, path collisions, traversal, and idempotency drift', () => {
  const store = new MemoryDocumentStore();
  store.upsert(fixture.create);
  assert.throws(() => store.upsert({ ...fixture.rename, expectedRevision: 0 }), /revision_conflict/);
  assert.throws(() => store.upsert({ ...fixture.rename, document: { ...fixture.rename.document, path: '../escape.md' } }), /document_invalid/);
  assert.throws(() => store.upsert({ ...fixture.create, text: 'changed' }), /document_idempotency_conflict/);

  const other = structuredClone(fixture.create);
  other.document.documentId = 'doc_01JYYYYYYYYYYYYYYYYYYYYYYY';
  other.idempotencyKey = `doc:vault-personal:${other.document.documentId.slice(4)}:1:${other.document.contentDigest.slice(7)}`;
  assert.throws(() => store.upsert(other), /document_path_conflict/);
});

test('PostgreSQL store conforms to the same lifecycle with parameterized transactions', async () => {
  const pool = new FakeDocumentPool(); const store = new PostgresDocumentStore({ pool });
  assert.equal((await store.upsert(fixture.create)).duplicate, false);
  assert.equal((await store.upsert(fixture.create)).duplicate, true);
  await store.upsert(fixture.rename);
  assert.equal((await store.search({ query: 'memory fabric', vaultIds: ['vault-personal'], limit: 20 })).length, 1);
  assert.equal((await store.read({ documentId: fixture.create.document.documentId, revision: 1 })).path, fixture.create.document.path);
  await store.delete(fixture.delete);
  assert.equal((await store.search({ query: 'memory', vaultIds: ['vault-personal'], limit: 20 })).length, 0);
  assert.equal((await store.health()).documents, 1);
  assert.ok(pool.queries.some(item => item.text.includes('pg_advisory_xact_lock')));
  for (const item of pool.queries.filter(item => item.values.length)) assert.equal(item.text.includes(fixture.create.document.documentId), false);
});
