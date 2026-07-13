import crypto from 'node:crypto';
import Database from 'better-sqlite3';
import pg from 'pg';

const { Pool } = pg;
const DOCUMENT_ID = /^doc_[A-Za-z0-9_-]{16,128}$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9:._-]{0,191}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const IDEMPOTENCY_KEY = /^doc:[A-Za-z0-9._-]+:[A-Za-z0-9_-]+:[1-9][0-9]*:[a-f0-9]{64}$/;

function failure(message, status = 400) {
  throw Object.assign(new Error(message), { status });
}

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}

function digest(value) {
  return crypto.createHash('sha256').update(canonical(value), 'utf8').digest('hex');
}

function plainObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value);
}

function safeRelativePath(value) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 4096 || value.startsWith('/') || value.includes('\0')) return false;
  return !value.split('/').includes('..');
}

function exactKeys(value, keys) {
  return plainObject(value) && Object.keys(value).sort().join('\0') === [...keys].sort().join('\0');
}

function validateExtraction(value) {
  const keys = ['status', 'extractor', 'provider', 'textDigest', 'errorCode'];
  if (!exactKeys(value, keys) || !['not_requested', 'pending', 'extracted', 'unsupported', 'failed'].includes(value.status)) failure('document_invalid');
  for (const key of ['extractor', 'provider', 'errorCode']) if (value[key] !== null && (typeof value[key] !== 'string' || value[key].length > 128)) failure('document_invalid');
  if (value.textDigest !== null && !DIGEST.test(value.textDigest)) failure('document_invalid');
  if (value.status === 'extracted' && !DIGEST.test(value.textDigest || '')) failure('document_invalid');
  if (value.status === 'failed' && !value.errorCode) failure('document_invalid');
}

export function validateDocumentRequest(request, { deleting = false } = {}) {
  const requestKeys = deleting ? ['document', 'expectedRevision', 'idempotencyKey'] : ['document', 'text', 'expectedRevision', 'idempotencyKey'];
  if (!exactKeys(request, requestKeys)) failure('document_invalid');
  const document = request.document;
  const documentKeys = ['schema', 'documentId', 'vaultId', 'path', 'previousPath', 'revision', 'contentDigest', 'mediaType', 'sourceModifiedAt', 'tombstone', 'extraction', 'provenance'];
  if (!exactKeys(document, documentKeys) || document.schema !== 'amf.document/v1' || !DOCUMENT_ID.test(document.documentId)
    || !IDENTIFIER.test(document.vaultId) || !safeRelativePath(document.path) || (document.previousPath !== null && !safeRelativePath(document.previousPath))
    || !Number.isSafeInteger(document.revision) || document.revision < 1 || !DIGEST.test(document.contentDigest)
    || typeof document.mediaType !== 'string' || !document.mediaType || document.mediaType.length > 255
    || (document.sourceModifiedAt !== null && !Number.isFinite(Date.parse(document.sourceModifiedAt))) || typeof document.tombstone !== 'boolean') failure('document_invalid');
  validateExtraction(document.extraction);
  const provenance = document.provenance;
  if (!exactKeys(provenance, ['sourceKind', 'sourceInstance', 'observedAt', 'actor']) || provenance.sourceKind !== 'obsidian'
    || !IDENTIFIER.test(provenance.sourceInstance) || !IDENTIFIER.test(provenance.actor) || !Number.isFinite(Date.parse(provenance.observedAt))) failure('document_invalid');
  if (!IDEMPOTENCY_KEY.test(request.idempotencyKey) || request.idempotencyKey !== `doc:${document.vaultId}:${document.documentId.slice(4)}:${document.revision}:${document.contentDigest.slice(7)}`) failure('document_invalid');
  if (request.expectedRevision !== null && (!Number.isSafeInteger(request.expectedRevision) || request.expectedRevision < 0)) failure('document_invalid');
  if (deleting) {
    if (!document.tombstone || request.expectedRevision === null) failure('document_invalid');
  } else {
    if (document.tombstone || (request.text !== null && (typeof request.text !== 'string' || request.text.length > 16 * 1024 * 1024))) failure('document_invalid');
    if (document.extraction.status === 'extracted' && typeof request.text !== 'string') failure('document_invalid');
  }
  return request;
}

function storedRevision(request) {
  return { ...structuredClone(request.document), text: request.text ?? null, idempotencyKey: request.idempotencyKey, requestDigest: digest(request) };
}

function assertTransition(current, request) {
  const { document, expectedRevision } = request;
  if (!current) {
    if (expectedRevision !== null || document.revision !== 1) failure('revision_conflict', 409);
    return;
  }
  if (current.vaultId !== document.vaultId || expectedRevision !== current.revision || document.revision !== current.revision + 1) failure('revision_conflict', 409);
}

function searchRows(rows, { query, vaultIds, limit = 20 }) {
  if (typeof query !== 'string' || !query || query.length > 4096 || !Array.isArray(vaultIds) || !vaultIds.length || vaultIds.some(value => !IDENTIFIER.test(value))
    || !Number.isSafeInteger(limit) || limit < 1 || limit > 100) failure('document_invalid');
  const needle = query.toLocaleLowerCase('en-US');
  const allowed = new Set(vaultIds);
  return rows.filter(row => !row.tombstone && allowed.has(row.vaultId) && `${row.path}\n${row.text || ''}`.toLocaleLowerCase('en-US').includes(needle))
    .sort((left, right) => left.path.localeCompare(right.path) || left.documentId.localeCompare(right.documentId)).slice(0, limit).map(row => structuredClone(row));
}

export class MemoryDocumentStore {
  constructor() { this.heads = new Map(); this.revisions = new Map(); this.idempotency = new Map(); }

  write(request, { deleting = false } = {}) {
    validateDocumentRequest(request, { deleting });
    const requestDigest = digest(request);
    const replay = this.idempotency.get(request.idempotencyKey);
    if (replay) {
      if (replay.requestDigest !== requestDigest) failure('document_idempotency_conflict', 409);
      return { document: structuredClone(replay.document), duplicate: true };
    }
    const current = this.heads.get(request.document.documentId) || null;
    assertTransition(current, request);
    for (const row of this.heads.values()) if (!request.document.tombstone && !row.tombstone && row.vaultId === request.document.vaultId
      && row.path === request.document.path && row.documentId !== request.document.documentId) failure('document_path_conflict', 409);
    const row = storedRevision(request);
    this.revisions.set(`${row.documentId}\0${row.revision}`, row); this.heads.set(row.documentId, row); this.idempotency.set(request.idempotencyKey, row);
    return { document: structuredClone(row), duplicate: false };
  }

  upsert(request) { return this.write(request); }
  delete(request) { return this.write(request, { deleting: true }); }
  read({ documentId, revision = null }) {
    if (!DOCUMENT_ID.test(documentId) || (revision !== null && (!Number.isSafeInteger(revision) || revision < 1))) failure('document_invalid');
    const row = revision === null ? this.heads.get(documentId) : this.revisions.get(`${documentId}\0${revision}`);
    if (!row) failure('document_not_found', 404);
    return structuredClone(row);
  }
  search(request) { return searchRows([...this.heads.values()], request); }
  health() { return { healthy: true, backend: 'memory', documents: this.heads.size }; }
}

function mapSqlite(row) {
  if (!row) return null;
  return {
    schema: 'amf.document/v1', documentId: row.document_id, vaultId: row.vault_id, path: row.path, previousPath: row.previous_path,
    revision: row.revision, contentDigest: row.content_digest, mediaType: row.media_type, sourceModifiedAt: row.source_modified_at,
    tombstone: Boolean(row.tombstone), extraction: JSON.parse(row.extraction_json), provenance: JSON.parse(row.provenance_json),
    text: row.text_content, idempotencyKey: row.idempotency_key, requestDigest: row.request_digest
  };
}

export class SqliteDocumentStore {
  constructor({ filename = ':memory:', database } = {}) {
    this.db = database || new Database(filename);
    this.db.pragma('foreign_keys = ON');
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS document_revisions_v1 (
        document_id TEXT NOT NULL, vault_id TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision >= 1), path TEXT NOT NULL,
        previous_path TEXT, content_digest TEXT NOT NULL, media_type TEXT NOT NULL, source_modified_at TEXT, tombstone INTEGER NOT NULL CHECK(tombstone IN (0,1)),
        extraction_json TEXT NOT NULL, provenance_json TEXT NOT NULL, text_content TEXT, idempotency_key TEXT NOT NULL UNIQUE, request_digest TEXT NOT NULL,
        PRIMARY KEY(document_id, revision)
      );
      CREATE TABLE IF NOT EXISTS document_heads_v1 (
        document_id TEXT PRIMARY KEY, vault_id TEXT NOT NULL, revision INTEGER NOT NULL, path TEXT NOT NULL, tombstone INTEGER NOT NULL,
        FOREIGN KEY(document_id, revision) REFERENCES document_revisions_v1(document_id, revision)
      );
      CREATE UNIQUE INDEX IF NOT EXISTS document_heads_v1_live_path ON document_heads_v1(vault_id,path) WHERE tombstone=0;
    `);
    this.writeTransaction = this.db.transaction((request, deleting) => this.writeInside(request, deleting));
  }

  writeInside(request, deleting) {
    validateDocumentRequest(request, { deleting });
    const requestDigest = digest(request);
    const replayRow = this.db.prepare('SELECT * FROM document_revisions_v1 WHERE idempotency_key=?').get(request.idempotencyKey);
    if (replayRow) {
      if (replayRow.request_digest !== requestDigest) failure('document_idempotency_conflict', 409);
      return { document: mapSqlite(replayRow), duplicate: true };
    }
    const current = mapSqlite(this.db.prepare('SELECT r.* FROM document_heads_v1 h JOIN document_revisions_v1 r ON r.document_id=h.document_id AND r.revision=h.revision WHERE h.document_id=?').get(request.document.documentId));
    assertTransition(current, request);
    const row = storedRevision(request);
    try {
      this.db.prepare(`INSERT INTO document_revisions_v1(document_id,vault_id,revision,path,previous_path,content_digest,media_type,source_modified_at,tombstone,extraction_json,provenance_json,text_content,idempotency_key,request_digest)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(row.documentId, row.vaultId, row.revision, row.path, row.previousPath, row.contentDigest, row.mediaType, row.sourceModifiedAt,
        row.tombstone ? 1 : 0, JSON.stringify(row.extraction), JSON.stringify(row.provenance), row.text, row.idempotencyKey, row.requestDigest);
      this.db.prepare(`INSERT INTO document_heads_v1(document_id,vault_id,revision,path,tombstone) VALUES (?,?,?,?,?)
        ON CONFLICT(document_id) DO UPDATE SET vault_id=excluded.vault_id,revision=excluded.revision,path=excluded.path,tombstone=excluded.tombstone`).run(row.documentId, row.vaultId, row.revision, row.path, row.tombstone ? 1 : 0);
    } catch (error) {
      if (String(error?.code).startsWith('SQLITE_CONSTRAINT')) failure('document_path_conflict', 409);
      throw error;
    }
    return { document: row, duplicate: false };
  }

  upsert(request) { return this.writeTransaction(request, false); }
  delete(request) { return this.writeTransaction(request, true); }
  read({ documentId, revision = null }) {
    if (!DOCUMENT_ID.test(documentId) || (revision !== null && (!Number.isSafeInteger(revision) || revision < 1))) failure('document_invalid');
    const row = revision === null
      ? this.db.prepare('SELECT r.* FROM document_heads_v1 h JOIN document_revisions_v1 r ON r.document_id=h.document_id AND r.revision=h.revision WHERE h.document_id=?').get(documentId)
      : this.db.prepare('SELECT * FROM document_revisions_v1 WHERE document_id=? AND revision=?').get(documentId, revision);
    if (!row) failure('document_not_found', 404);
    return mapSqlite(row);
  }
  search(request) {
    const placeholders = request.vaultIds.map(() => '?').join(',');
    const rows = this.db.prepare(`SELECT r.* FROM document_heads_v1 h JOIN document_revisions_v1 r ON r.document_id=h.document_id AND r.revision=h.revision
      WHERE h.tombstone=0 AND h.vault_id IN (${placeholders})`).all(...request.vaultIds).map(mapSqlite);
    return searchRows(rows, request);
  }
  health() { return { healthy: true, backend: 'sqlite', documents: this.db.prepare('SELECT count(*) AS count FROM document_heads_v1').get().count }; }
  close() { if (this.db.open) this.db.close(); }
}

const POSTGRES_DDL = `
CREATE SCHEMA IF NOT EXISTS agent_memory_fabric;
CREATE TABLE IF NOT EXISTS agent_memory_fabric.document_revisions_v1 (
  document_id TEXT NOT NULL, vault_id TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision >= 1), path TEXT NOT NULL,
  previous_path TEXT, content_digest TEXT NOT NULL, media_type TEXT NOT NULL, source_modified_at TIMESTAMPTZ, tombstone BOOLEAN NOT NULL,
  extraction_json JSONB NOT NULL, provenance_json JSONB NOT NULL, text_content TEXT, idempotency_key TEXT NOT NULL UNIQUE, request_digest TEXT NOT NULL,
  PRIMARY KEY(document_id, revision)
);
CREATE TABLE IF NOT EXISTS agent_memory_fabric.document_heads_v1 (
  document_id TEXT PRIMARY KEY, vault_id TEXT NOT NULL, revision INTEGER NOT NULL, path TEXT NOT NULL, tombstone BOOLEAN NOT NULL,
  FOREIGN KEY(document_id, revision) REFERENCES agent_memory_fabric.document_revisions_v1(document_id, revision)
);
CREATE UNIQUE INDEX IF NOT EXISTS document_heads_v1_live_path ON agent_memory_fabric.document_heads_v1(vault_id,path) WHERE tombstone=false;
`;

function mapPostgres(row) {
  if (!row) return null;
  return mapSqlite({ ...row, tombstone: row.tombstone ? 1 : 0, extraction_json: typeof row.extraction_json === 'string' ? row.extraction_json : JSON.stringify(row.extraction_json),
    provenance_json: typeof row.provenance_json === 'string' ? row.provenance_json : JSON.stringify(row.provenance_json), source_modified_at: row.source_modified_at ? new Date(row.source_modified_at).toISOString() : null });
}

export class PostgresDocumentStore {
  constructor({ pool, connectionString, poolFactory = config => new Pool(config) } = {}) {
    this.pool = pool || poolFactory({ connectionString, max: 10 });
    this.initialized = this.pool.query(POSTGRES_DDL);
  }
  async ready() { await this.initialized; return this; }
  async write(request, { deleting = false } = {}) {
    validateDocumentRequest(request, { deleting }); await this.ready();
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [request.document.documentId]);
      const replay = (await client.query('SELECT * FROM agent_memory_fabric.document_revisions_v1 WHERE idempotency_key=$1', [request.idempotencyKey])).rows[0];
      const requestDigest = digest(request);
      if (replay) {
        if (replay.request_digest !== requestDigest) failure('document_idempotency_conflict', 409);
        await client.query('COMMIT'); return { document: mapPostgres(replay), duplicate: true };
      }
      const currentRow = (await client.query(`SELECT r.* FROM agent_memory_fabric.document_heads_v1 h JOIN agent_memory_fabric.document_revisions_v1 r
        ON r.document_id=h.document_id AND r.revision=h.revision WHERE h.document_id=$1 FOR UPDATE`, [request.document.documentId])).rows[0];
      assertTransition(mapPostgres(currentRow), request);
      const row = storedRevision(request);
      await client.query(`INSERT INTO agent_memory_fabric.document_revisions_v1(document_id,vault_id,revision,path,previous_path,content_digest,media_type,source_modified_at,tombstone,extraction_json,provenance_json,text_content,idempotency_key,request_digest)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,$12,$13,$14)`, [row.documentId, row.vaultId, row.revision, row.path, row.previousPath, row.contentDigest, row.mediaType, row.sourceModifiedAt,
        row.tombstone, JSON.stringify(row.extraction), JSON.stringify(row.provenance), row.text, row.idempotencyKey, row.requestDigest]);
      await client.query(`INSERT INTO agent_memory_fabric.document_heads_v1(document_id,vault_id,revision,path,tombstone) VALUES ($1,$2,$3,$4,$5)
        ON CONFLICT(document_id) DO UPDATE SET vault_id=excluded.vault_id,revision=excluded.revision,path=excluded.path,tombstone=excluded.tombstone`, [row.documentId, row.vaultId, row.revision, row.path, row.tombstone]);
      await client.query('COMMIT'); return { document: row, duplicate: false };
    } catch (error) {
      try { await client.query('ROLLBACK'); } catch {}
      if (error?.code === '23505') failure('document_path_conflict', 409);
      throw error;
    } finally { client.release(); }
  }
  upsert(request) { return this.write(request); }
  delete(request) { return this.write(request, { deleting: true }); }
  async read({ documentId, revision = null }) {
    if (!DOCUMENT_ID.test(documentId) || (revision !== null && (!Number.isSafeInteger(revision) || revision < 1))) failure('document_invalid');
    await this.ready();
    const result = revision === null
      ? await this.pool.query(`SELECT r.* FROM agent_memory_fabric.document_heads_v1 h JOIN agent_memory_fabric.document_revisions_v1 r ON r.document_id=h.document_id AND r.revision=h.revision WHERE h.document_id=$1`, [documentId])
      : await this.pool.query('SELECT * FROM agent_memory_fabric.document_revisions_v1 WHERE document_id=$1 AND revision=$2', [documentId, revision]);
    if (!result.rows[0]) failure('document_not_found', 404);
    return mapPostgres(result.rows[0]);
  }
  async search(request) {
    searchRows([], request); await this.ready();
    const rows = (await this.pool.query(`SELECT r.* FROM agent_memory_fabric.document_heads_v1 h JOIN agent_memory_fabric.document_revisions_v1 r
      ON r.document_id=h.document_id AND r.revision=h.revision WHERE h.tombstone=false AND h.vault_id=ANY($1::text[])`, [request.vaultIds])).rows.map(mapPostgres);
    return searchRows(rows, request);
  }
  async health() { await this.ready(); const result = await this.pool.query('SELECT count(*)::bigint AS count FROM agent_memory_fabric.document_heads_v1'); return { healthy: true, backend: 'postgresql', documents: Number(result.rows[0].count) }; }
  async close() { await this.pool.end(); }
}

export function createDocumentStoreFromEnv(env = process.env) {
  const backend = String(env.AMF_DOCUMENT_BACKEND || '').trim();
  if (backend === 'sqlite') return new SqliteDocumentStore({ filename: env.AMF_DOCUMENT_SQLITE_PATH || ':memory:' });
  if (backend === 'postgresql') {
    if (!env.AMF_POSTGRES_URL) failure('document_store_unconfigured', 503);
    return new PostgresDocumentStore({ connectionString: env.AMF_POSTGRES_URL });
  }
  failure('document_store_unconfigured', 503);
}
