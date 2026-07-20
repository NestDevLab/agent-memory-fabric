import assert from 'node:assert/strict';
import test from 'node:test';

import {
  SemanticIndex,
  createOllamaEmbedder,
  createSemanticIndexFromEnv,
  createUnconfiguredSemanticIndex,
  embeddableClaimText,
  reindexSemanticIndex
} from '../src/semantic-index.mjs';
import { CanonicalPamBridge } from '../src/canonical-memory-bridge.mjs';

const DIMS = 4;

function unitVector(seed) {
  const raw = Array.from({ length: DIMS }, (_, i) => Math.sin(seed * (i + 1)) + 0.001);
  const norm = Math.sqrt(raw.reduce((sum, value) => sum + value * value, 0));
  return raw.map(value => value / norm);
}

function cosineDistance(a, b) {
  const dot = a.reduce((sum, value, i) => sum + value * b[i], 0);
  return 1 - dot;
}

// A deterministic fake embedder plus an in-memory pgvector stand-in whose KNN
// mirrors the SQL: filter by scope, order by cosine distance, bound by limit.
function fakeEmbedder(vectorForText) {
  return async (texts) => texts.map(text => vectorForText(String(text)));
}

class FakePgvector {
  constructor() { this.rows = new Map(); this.queries = []; }
  async query(text, values = []) {
    this.queries.push({ text, values });
    const compact = text.replace(/\s+/g, ' ').trim();
    if (compact.startsWith('CREATE TABLE') || compact.startsWith('CREATE INDEX')) return { rows: [] };
    if (compact.startsWith('INSERT INTO agent_memory_fabric.canonical_embeddings_v1')) {
      const [recordId, scope, claimText, literal] = values;
      this.rows.set(recordId, { record_id: recordId, scope, claim_text: claimText, embedding: JSON.parse(literal) });
      return { rows: [] };
    }
    if (compact.startsWith('DELETE FROM agent_memory_fabric.canonical_embeddings_v1')) {
      this.rows.delete(values[0]);
      return { rows: [] };
    }
    if (compact.startsWith('SELECT record_id, claim_text FROM agent_memory_fabric.canonical_embeddings_v1')) {
      return { rows: [...this.rows.values()].map(row => ({ record_id: row.record_id, claim_text: row.claim_text })) };
    }
    if (compact.startsWith('SELECT record_id FROM agent_memory_fabric.canonical_embeddings_v1')) {
      return { rows: [...this.rows.values()].map(row => ({ record_id: row.record_id })) };
    }
    if (compact.startsWith('SELECT record_id, embedding')) {
      const queryVector = JSON.parse(values[0]);
      const scopes = new Set(values[1]);
      const limit = values[2];
      return { rows: [...this.rows.values()]
        .filter(row => scopes.has(row.scope))
        .map(row => ({ record_id: row.record_id, distance: cosineDistance(queryVector, row.embedding) }))
        .sort((a, b) => a.distance - b.distance)
        .slice(0, limit) };
    }
    throw new Error(`unexpected_sql: ${compact.slice(0, 40)}`);
  }
  on() {}
  async end() {}
}

function makeIndex({ embedder, maxDistance = 0.55, topK = 10 } = {}) {
  const pool = new FakePgvector();
  const index = new SemanticIndex({ pool, embedder, dims: DIMS, maxDistance, topK });
  return { index, pool };
}

test('upsert embeds and persists; searchIds returns scope-filtered nearest within threshold', async () => {
  const vectors = {
    'Utrecht da tre anni': unitVector(1),
    'moka non le cialde': unitVector(2),
    'dove abita': unitVector(1.02),
    'un caffe': unitVector(2.02),
    'niente di simile': unitVector(9)
  };
  const { index, pool } = makeIndex({ embedder: fakeEmbedder(text => vectors[text] ?? unitVector(50)) });
  await index.upsert({ recordId: 'mem_city0001aaaaaaaa', scope: 'agent:vitae', claimText: 'Utrecht da tre anni' });
  await index.upsert({ recordId: 'mem_moka0001aaaaaaaa', scope: 'agent:vitae', claimText: 'moka non le cialde' });
  assert.equal(pool.rows.size, 2);

  const cityHit = await index.searchIds({ query: 'dove abita', scopes: ['agent:vitae'] });
  assert.deepEqual(cityHit, ['mem_city0001aaaaaaaa']);
  const coffeeHit = await index.searchIds({ query: 'un caffe', scopes: ['agent:vitae'] });
  assert.deepEqual(coffeeHit, ['mem_moka0001aaaaaaaa']);
  const noScope = await index.searchIds({ query: 'dove abita', scopes: ['relationship:vitae:joseph'] });
  assert.deepEqual(noScope, []);
  const farQuery = await index.searchIds({ query: 'niente di simile', scopes: ['agent:vitae'] });
  assert.deepEqual(farQuery, []);
});

test('upsert is idempotent on record id and rejects malformed inputs', async () => {
  const { index, pool } = makeIndex({ embedder: fakeEmbedder(() => unitVector(3)) });
  await index.upsert({ recordId: 'mem_dup00001aaaaaaaa', scope: 'agent:vitae', claimText: 'first' });
  await index.upsert({ recordId: 'mem_dup00001aaaaaaaa', scope: 'agent:vitae', claimText: 'second' });
  assert.equal(pool.rows.size, 1);
  assert.equal(pool.rows.get('mem_dup00001aaaaaaaa').claim_text, 'second');
  await assert.rejects(index.upsert({ recordId: 'not-a-mem-id', scope: 'agent:vitae', claimText: 'x' }), /semantic_record_id_invalid/);
  await assert.rejects(index.upsert({ recordId: 'mem_ok000001aaaaaaaa', scope: 'bad scope', claimText: 'x' }), /semantic_scope_invalid/);
  await assert.rejects(index.upsert({ recordId: 'mem_ok000001aaaaaaaa', scope: 'agent:vitae', claimText: '   ' }), /semantic_claim_text_empty/);
});

test('embedder shape mismatches fail closed', async () => {
  const { index } = makeIndex({ embedder: async () => [[1, 2]] });
  await assert.rejects(index.upsert({ recordId: 'mem_bad00001aaaaaaaa', scope: 'agent:vitae', claimText: 'x' }), /semantic_embedding_shape_invalid/);
});

test('searchIds ignores empty query and empty/invalid scopes', async () => {
  const { index } = makeIndex({ embedder: fakeEmbedder(() => unitVector(4)) });
  assert.deepEqual(await index.searchIds({ query: '', scopes: ['agent:vitae'] }), []);
  assert.deepEqual(await index.searchIds({ query: 'x', scopes: [] }), []);
  assert.deepEqual(await index.searchIds({ query: 'x', scopes: ['bad scope'] }), []);
});

test('embeddableClaimText returns plain text only', () => {
  assert.equal(embeddableClaimText({ claim: { encoding: 'plain', text: '  hi  ' } }), 'hi');
  assert.equal(embeddableClaimText({ claim: { encoding: 'sealed', ciphertext: 'x' } }), '');
  assert.equal(embeddableClaimText({}), '');
});

test('reindex upserts plain records, skips sealed, and prunes vanished ids', async () => {
  const plain = (id, text) => ({ id, path: `memory/records/${id}.md`, claim: { encoding: 'plain', text } });
  const records = {
    mem_r1aaaaaaaaaaaaaa: plain('mem_r1aaaaaaaaaaaaaa', 'Utrecht'),
    mem_r2aaaaaaaaaaaaaa: plain('mem_r2aaaaaaaaaaaaaa', 'moka'),
    mem_sealedaaaaaaaaaa: { id: 'mem_sealedaaaaaaaaaa', path: 'memory/records/sealed.md', claim: { encoding: 'sealed' } }
  };
  const bridge = new CanonicalPamBridge({
    index: { records: Object.fromEntries(Object.entries(records).map(([id, r]) => [id, { path: r.path, scope: 'agent:vitae' }])) },
    async callTool(name, args) {
      if (name === 'memory_search') return { matches: [] };
      if (name === 'memory_record_validate') {
        const rec = Object.values(records).find(r => r.path === args.path);
        return rec ? { status: 'valid', metadata: { ...rec, id: rec.id, revision: 1, lifecycle: { status: 'active' } } } : { status: 'missing' };
      }
      throw new Error('unexpected_tool');
    }
  });
  bridge.read = async ({ id }) => {
    const rec = records[id];
    if (!rec) throw new Error('memory_not_found');
    return { id, revision: 1, lifecycle: { status: 'active' }, claim: rec.claim };
  };
  const { index, pool } = makeIndex({ embedder: fakeEmbedder(() => unitVector(7)) });
  pool.rows.set('mem_staleaaaaaaaaaaa', { record_id: 'mem_staleaaaaaaaaaaa', scope: 'agent:vitae', claim_text: 'old', embedding: unitVector(8) });

  const result = await reindexSemanticIndex({ semanticIndex: index, bridge });
  assert.deepEqual(result, { ok: true, upserted: 2, unchanged: 0, skipped: 1, failed: 0, removed: 1 });
  assert.ok(pool.rows.has('mem_r1aaaaaaaaaaaaaa'));
  assert.ok(pool.rows.has('mem_r2aaaaaaaaaaaaaa'));
  assert.equal(pool.rows.has('mem_sealedaaaaaaaaaa'), false);
  assert.equal(pool.rows.has('mem_staleaaaaaaaaaaa'), false);
});

test('reindex skips unchanged claims, re-embeds changed claims, and force re-embeds all claims', async () => {
  const records = {
    mem_firstaaaaaaaaaaa: { path: 'memory/records/first.md', text: 'Utrecht' },
    mem_secondaaaaaaaaaa: { path: 'memory/records/second.md', text: 'moka' }
  };
  const bridge = new CanonicalPamBridge({
    index: { records: Object.fromEntries(Object.entries(records).map(([id, record]) => [id, { path: record.path, scope: 'agent:vitae' }])) },
    async callTool() { return { matches: [] }; }
  });
  bridge.read = async ({ id }) => ({ id, revision: 1, lifecycle: { status: 'active' }, claim: { encoding: 'plain', text: records[id].text } });
  const embedded = [];
  const { index } = makeIndex({ embedder: async texts => {
    embedded.push(...texts);
    return texts.map(() => unitVector(12));
  } });

  assert.deepEqual(await reindexSemanticIndex({ semanticIndex: index, bridge }), {
    ok: true, upserted: 2, unchanged: 0, skipped: 0, failed: 0, removed: 0
  });
  assert.deepEqual(await reindexSemanticIndex({ semanticIndex: index, bridge }), {
    ok: true, upserted: 0, unchanged: 2, skipped: 0, failed: 0, removed: 0
  });
  assert.equal(embedded.length, 2);

  records.mem_firstaaaaaaaaaaa.text = 'Utrecht da tre anni';
  assert.deepEqual(await reindexSemanticIndex({ semanticIndex: index, bridge }), {
    ok: true, upserted: 1, unchanged: 1, skipped: 0, failed: 0, removed: 0
  });
  assert.deepEqual(embedded, ['Utrecht', 'moka', 'Utrecht da tre anni']);

  assert.deepEqual(await reindexSemanticIndex({ semanticIndex: index, bridge, force: true }), {
    ok: true, upserted: 2, unchanged: 0, skipped: 0, failed: 0, removed: 0
  });
  assert.deepEqual(embedded, ['Utrecht', 'moka', 'Utrecht da tre anni', 'Utrecht da tre anni', 'moka']);
});

test('reindex counts a poison record as failed and continues the batch', async () => {
  const records = {
    mem_good1aaaaaaaaaaa: { path: 'memory/records/good1.md', text: 'Utrecht' },
    mem_good2aaaaaaaaaaa: { path: 'memory/records/good2.md', text: 'moka' }
  };
  const bridge = new CanonicalPamBridge({
    index: { records: Object.fromEntries(Object.entries(records).map(([id, r]) => [id, { path: r.path, scope: 'agent:vitae' }])) },
    async callTool() { return { matches: [] }; }
  });
  bridge.read = async ({ id }) => ({ id, revision: 1, lifecycle: { status: 'active' }, claim: { encoding: 'plain', text: records[id].text } });
  const { index, pool } = makeIndex({ embedder: fakeEmbedder(() => unitVector(11)) });
  const realUpsert = index.upsert.bind(index);
  index.upsert = async (args) => { if (args.recordId === 'mem_good1aaaaaaaaaaa') throw new Error('embed_hiccup'); return realUpsert(args); };
  const result = await reindexSemanticIndex({ semanticIndex: index, bridge });
  assert.equal(result.ok, true);
  assert.equal(result.failed, 1);
  assert.equal(result.upserted, 1);
  assert.ok(pool.rows.has('mem_good2aaaaaaaaaaa'));
});

test('unconfigured index is inert and reindex refuses', async () => {
  const index = createUnconfiguredSemanticIndex();
  assert.equal(index.configured, false);
  assert.deepEqual(await index.searchIds({ query: 'x', scopes: ['agent:vitae'] }), []);
  assert.deepEqual(await reindexSemanticIndex({ semanticIndex: index, bridge: {} }), { ok: false, reason: 'semantic_index_unconfigured' });
  assert.equal(createSemanticIndexFromEnv({}).configured, false);
  assert.equal(createSemanticIndexFromEnv({ AMF_SEMANTIC_SEARCH_ENABLED: 'false' }).configured, false);
});

test('env factory requires embedder and database configuration when enabled', () => {
  assert.throws(() => createSemanticIndexFromEnv({ AMF_SEMANTIC_SEARCH_ENABLED: 'true' }), /semantic_embedder_unconfigured/);
  assert.throws(() => createSemanticIndexFromEnv({
    AMF_SEMANTIC_SEARCH_ENABLED: 'true',
    AMF_SEMANTIC_EMBEDDING_BASE_URL: 'http://x:11434',
    AMF_SEMANTIC_EMBEDDING_MODEL: 'nomic-embed-text'
  }), /semantic_database_url_required/);
});

test('ollama embedder posts a batch and returns vectors in order', async () => {
  const calls = [];
  const embedder = createOllamaEmbedder({
    baseUrl: 'http://embed:11434/',
    model: 'nomic-embed-text',
    dims: DIMS,
    fetcher: async (url, options) => {
      calls.push({ url, body: JSON.parse(options.body) });
      return { ok: true, async json() { return { embeddings: [unitVector(1), unitVector(2)] }; } };
    }
  });
  const out = await embedder(['a', 'b']);
  assert.equal(out.length, 2);
  assert.equal(calls[0].url, 'http://embed:11434/api/embed');
  assert.deepEqual(calls[0].body.input, ['a', 'b']);
  const bad = createOllamaEmbedder({ baseUrl: 'http://embed:11434', model: 'm', dims: DIMS, fetcher: async () => ({ ok: false, status: 503 }) });
  await assert.rejects(bad(['a']), /semantic_embedder_http_503/);
  assert.equal(createOllamaEmbedder({ baseUrl: '', model: 'm' }), null);
});
