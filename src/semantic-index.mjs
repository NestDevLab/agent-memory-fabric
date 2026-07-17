import pg from 'pg';

import { postgresSslConfig } from './fabric-store.mjs';

const { Pool } = pg;

const DEFAULT_DIMS = 768;
const DEFAULT_TOP_K = 10;
const DEFAULT_MAX_DISTANCE = 0.55;
const DEFAULT_TIMEOUT_MS = 8000;
const SCHEMA = 'agent_memory_fabric';
const TABLE = 'canonical_embeddings_v1';
const SAFE_SCOPE = /^[A-Za-z0-9][A-Za-z0-9._:-]{2,255}$/;
const SAFE_RECORD_ID = /^mem_[A-Za-z0-9][A-Za-z0-9_-]{7,127}$/;

function error(code, status = 500) {
  const err = new Error(code);
  err.status = status;
  return err;
}

function boundedInteger(value, fallback, { min, max }) {
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed >= min && parsed <= max ? parsed : fallback;
}

function boundedFloat(value, fallback, { min, max }) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= min && parsed <= max ? parsed : fallback;
}

function toVectorLiteral(vector, dims) {
  if (!Array.isArray(vector) || vector.length !== dims || vector.some(value => !Number.isFinite(value))) {
    throw error('semantic_embedding_shape_invalid');
  }
  return `[${vector.join(',')}]`;
}

// Ollama's /api/embed accepts a batch and returns embeddings in input order.
export function createOllamaEmbedder({ baseUrl, model, dims = DEFAULT_DIMS, timeoutMs = DEFAULT_TIMEOUT_MS, fetcher = fetch } = {}) {
  const base = String(baseUrl ?? '').trim().replace(/\/+$/, '');
  const modelName = String(model ?? '').trim();
  if (!base || !modelName) return null;
  const url = `${base}/api/embed`;
  return async function embed(texts) {
    const inputs = (Array.isArray(texts) ? texts : [texts]).map(text => String(text ?? ''));
    if (!inputs.length) return [];
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetcher(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ model: modelName, input: inputs }),
        signal: controller.signal
      });
      if (!response.ok) throw error('semantic_embedder_http_' + response.status, 502);
      const payload = await response.json();
      const embeddings = payload?.embeddings;
      if (!Array.isArray(embeddings) || embeddings.length !== inputs.length) throw error('semantic_embedder_response_invalid', 502);
      for (const vector of embeddings) {
        if (!Array.isArray(vector) || vector.length !== dims) throw error('semantic_embedder_dims_mismatch', 502);
      }
      return embeddings;
    } finally {
      clearTimeout(timer);
    }
  };
}

export class SemanticIndex {
  constructor({
    pool,
    connectionString,
    ssl,
    embedder,
    dims = DEFAULT_DIMS,
    topK = DEFAULT_TOP_K,
    maxDistance = DEFAULT_MAX_DISTANCE,
    poolFactory = (config) => new Pool(config),
    max = 4,
    connectTimeoutMs = 5000,
    queryTimeoutMs = 15000
  } = {}) {
    if (typeof embedder !== 'function') throw error('semantic_embedder_required');
    if (!pool && !connectionString) throw error('semantic_database_url_required');
    this.embedder = embedder;
    this.dims = dims;
    this.topK = topK;
    this.maxDistance = maxDistance;
    this.configured = true;
    this.pool = pool || poolFactory({
      connectionString,
      ssl,
      max,
      connectionTimeoutMillis: connectTimeoutMs,
      query_timeout: queryTimeoutMs,
      statement_timeout: queryTimeoutMs
    });
    this.pool.on?.('error', () => {});
  }

  // Idempotent table + index provisioning. The `vector` extension is a
  // superuser prerequisite (documented) — the app role cannot CREATE EXTENSION,
  // so this asserts the table and cosine HNSW index only.
  async ensureSchema() {
    await this.pool.query(`CREATE TABLE IF NOT EXISTS ${SCHEMA}.${TABLE} (
      record_id  text PRIMARY KEY,
      scope      text NOT NULL,
      claim_text text NOT NULL,
      embedding  vector(${this.dims}) NOT NULL,
      updated_at timestamptz NOT NULL DEFAULT now()
    )`);
    await this.pool.query(`CREATE INDEX IF NOT EXISTS ${TABLE}_scope_idx ON ${SCHEMA}.${TABLE} (scope)`);
    await this.pool.query(`CREATE INDEX IF NOT EXISTS ${TABLE}_hnsw ON ${SCHEMA}.${TABLE} USING hnsw (embedding vector_cosine_ops)`);
  }

  async upsert({ recordId, scope, claimText }) {
    if (!SAFE_RECORD_ID.test(String(recordId ?? ''))) throw error('semantic_record_id_invalid', 400);
    if (!SAFE_SCOPE.test(String(scope ?? ''))) throw error('semantic_scope_invalid', 400);
    const text = String(claimText ?? '').trim();
    if (!text) throw error('semantic_claim_text_empty', 400);
    const [vector] = await this.embedder([text]);
    const literal = toVectorLiteral(vector, this.dims);
    await this.pool.query(
      `INSERT INTO ${SCHEMA}.${TABLE} (record_id, scope, claim_text, embedding, updated_at)
       VALUES ($1, $2, $3, $4::vector, now())
       ON CONFLICT (record_id) DO UPDATE
         SET scope = EXCLUDED.scope, claim_text = EXCLUDED.claim_text, embedding = EXCLUDED.embedding, updated_at = now()`,
      [recordId, scope, text, literal]
    );
  }

  async remove(recordId) {
    if (!SAFE_RECORD_ID.test(String(recordId ?? ''))) return;
    await this.pool.query(`DELETE FROM ${SCHEMA}.${TABLE} WHERE record_id = $1`, [recordId]);
  }

  async listRecordIds() {
    const result = await this.pool.query(`SELECT record_id FROM ${SCHEMA}.${TABLE}`);
    return result.rows.map(row => row.record_id);
  }

  // Returns the record ids of the nearest records within the allowed scopes,
  // bounded by topK and the maximum cosine distance. Scope and privacy are
  // re-checked downstream; this is a recall stage, not an authorization gate.
  async searchIds({ query, scopes, limit = this.topK }) {
    const text = String(query ?? '').trim();
    const allowed = [...new Set((Array.isArray(scopes) ? scopes : []).filter(scope => SAFE_SCOPE.test(String(scope ?? ''))))];
    if (!text || !allowed.length) return [];
    const [vector] = await this.embedder([text]);
    const literal = toVectorLiteral(vector, this.dims);
    const bounded = boundedInteger(limit, this.topK, { min: 1, max: 100 });
    const result = await this.pool.query(
      `SELECT record_id, embedding <=> $1::vector AS distance
         FROM ${SCHEMA}.${TABLE}
        WHERE scope = ANY($2::text[])
        ORDER BY embedding <=> $1::vector
        LIMIT $3`,
      [literal, allowed, bounded]
    );
    return result.rows
      .filter(row => Number(row.distance) <= this.maxDistance)
      .map(row => row.record_id);
  }

  async close() {
    if (this._closed) return;
    this._closed = true;
    await this.pool.end?.();
  }
}

export function createUnconfiguredSemanticIndex() {
  return {
    configured: false,
    async searchIds() { return []; },
    async upsert() { throw error('semantic_index_unconfigured', 503); },
    async remove() {},
    async listRecordIds() { return []; },
    async close() {}
  };
}

export function createSemanticIndexFromEnv(env = process.env) {
  if (String(env.AMF_SEMANTIC_SEARCH_ENABLED || '').trim() !== 'true') return createUnconfiguredSemanticIndex();
  const dims = boundedInteger(env.AMF_SEMANTIC_EMBEDDING_DIMS, DEFAULT_DIMS, { min: 8, max: 8192 });
  const embedder = createOllamaEmbedder({
    baseUrl: env.AMF_SEMANTIC_EMBEDDING_BASE_URL,
    model: env.AMF_SEMANTIC_EMBEDDING_MODEL,
    dims,
    timeoutMs: boundedInteger(env.AMF_SEMANTIC_EMBEDDING_TIMEOUT_MS, DEFAULT_TIMEOUT_MS, { min: 500, max: 60000 })
  });
  if (!embedder) throw error('semantic_embedder_unconfigured');
  const connectionString = String(env.AMF_SEMANTIC_DATABASE_URL || env.AMF_CATALOG_DATABASE_URL || '').trim();
  if (!connectionString) throw error('semantic_database_url_required');
  return new SemanticIndex({
    connectionString,
    ssl: postgresSslConfig(env),
    embedder,
    dims,
    topK: boundedInteger(env.AMF_SEMANTIC_TOP_K, DEFAULT_TOP_K, { min: 1, max: 100 }),
    maxDistance: boundedFloat(env.AMF_SEMANTIC_MAX_DISTANCE, DEFAULT_MAX_DISTANCE, { min: 0, max: 2 })
  });
}

// Claim text for embedding: plain text as stored. Sealed claims are skipped —
// their ciphertext carries no lexical signal.
export function embeddableClaimText(record) {
  if (record?.claim?.encoding !== 'plain') return '';
  return String(record.claim.text ?? '').trim();
}

export async function reindexSemanticIndex({ semanticIndex, bridge, log = () => {} }) {
  if (!semanticIndex?.configured) return { ok: false, reason: 'semantic_index_unconfigured' };
  if (typeof semanticIndex.ensureSchema === 'function') await semanticIndex.ensureSchema();
  const index = bridge.refreshIndex();
  const entries = Object.entries(index.records || {});
  const present = new Set();
  let upserted = 0;
  let skipped = 0;
  let failed = 0;
  for (const [id, entry] of entries) {
    let record;
    try {
      record = await bridge.read({ id });
    } catch {
      skipped += 1;
      continue;
    }
    const text = embeddableClaimText(record);
    if (!text) { skipped += 1; continue; }
    // One poison record (embed hiccup, malformed scope/id) must not abort the
    // whole batch; upsert is idempotent so a later run recovers it.
    try {
      await semanticIndex.upsert({ recordId: id, scope: entry.scope, claimText: text });
      present.add(id);
      upserted += 1;
    } catch (error) {
      failed += 1;
      log(`semantic reindex: skip ${id}: ${String(error?.message || 'upsert_failed')}`);
    }
  }
  let removed = 0;
  for (const id of await semanticIndex.listRecordIds()) {
    if (!present.has(id)) { await semanticIndex.remove(id); removed += 1; }
  }
  log(`semantic reindex: upserted=${upserted} skipped=${skipped} failed=${failed} removed=${removed}`);
  return { ok: true, upserted, skipped, failed, removed };
}
