import crypto from 'node:crypto';
import Database from 'better-sqlite3';
import pg from 'pg';

export const CAPABILITY_OPAQUE_REFERENCE_SCHEMA_VERSION = 1;
const { Pool } = pg;
const RESOURCE_ID = /^rid_[A-Za-z0-9_-]{8,128}$/;
const CURSOR_ID = /^cur_[A-Za-z0-9_-]{16,256}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const KINDS = new Set(['canonical_memory', 'document', 'conversation', 'proposal']);
const INVALID_INPUT = 'capability_opaque_reference_invalid';
const RETIRED = 'capability_opaque_reference_retired';
const UNAVAILABLE = 'capability_opaque_reference_unavailable';
const NOT_FOUND = 'capability_resource_not_found';
const CURSOR_INVALID = 'capability_cursor_invalid';
const INVALID = Symbol('invalid');
const MAX_RETRIES = 16;
const OWN_ERRORS = new WeakSet();

function error(code) { const value = Object.assign(new Error(code), { code }); OWN_ERRORS.add(value); return value; }
function fail(code) { throw error(code); }
function frozen(value) { if (value && typeof value === 'object' && !Object.isFrozen(value)) { for (const key of Object.keys(value)) frozen(value[key]); Object.freeze(value); } return value; }
function canonical(value) { if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`; if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`; return JSON.stringify(value); }
function digest(value) { return `sha256:${crypto.createHash('sha256').update(canonical(value), 'utf8').digest('hex')}`; }
function text(value, max = 4096) { return typeof value === 'string' && value.length > 0 && value.length <= max && !value.includes('\0'); }
async function clean(code, action) { try { return await action(); } catch (cause) { if (OWN_ERRORS.has(cause) && (cause.code === code || cause.code === INVALID_INPUT || cause.code === RETIRED)) throw cause; throw error(code); } }

/** Snapshot an own, enumerable, data-only record exactly once before reading it. */
function record(value, keys = null) {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) return null;
    const ownKeys = Reflect.ownKeys(value);
    if (ownKeys.some(key => typeof key !== 'string') || (keys && (ownKeys.length !== keys.length || !keys.every(key => ownKeys.includes(key))))) return null;
    const out = {};
    for (const key of ownKeys) { const descriptor = Object.getOwnPropertyDescriptor(value, key); if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) return null; Object.defineProperty(out, key, { value: descriptor.value, enumerable: true, writable: false, configurable: false }); }
    return out;
  } catch { return null; }
}

function copyJsonInner(value, state, visiting, depth) {
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'string') return value.length <= 4096 ? value : INVALID;
  if (typeof value === 'number') return Number.isFinite(value) ? value : INVALID;
  if (!value || typeof value !== 'object' || depth >= 8 || visiting.has(value)) return INVALID;
  try {
    visiting.add(value);
    const keys = Reflect.ownKeys(value);
    if (keys.some(key => typeof key !== 'string') || (state.keys += keys.length) > 128) return INVALID;
    if (Array.isArray(value)) {
      const length = Object.getOwnPropertyDescriptor(value, 'length');
      if (!length || !Object.hasOwn(length, 'value') || !Number.isSafeInteger(length.value) || length.value > 128 || keys.length !== length.value + 1) return INVALID;
      const out = [];
      for (let index = 0; index < length.value; index += 1) { const descriptor = Object.getOwnPropertyDescriptor(value, String(index)); if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) return INVALID; const copied = copyJsonInner(descriptor.value, state, visiting, depth + 1); if (copied === INVALID) return INVALID; out.push(copied); }
      return out;
    }
    if (Object.getPrototypeOf(value) !== Object.prototype) return INVALID;
    const out = {};
    for (const key of [...keys].sort()) { const descriptor = Object.getOwnPropertyDescriptor(value, key); if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) return INVALID; const copied = copyJsonInner(descriptor.value, state, visiting, depth + 1); if (copied === INVALID) return INVALID; Object.defineProperty(out, key, { value: copied, enumerable: true, writable: true, configurable: true }); }
    return out;
  } catch { return INVALID; } finally { try { visiting.delete(value); } catch {} }
}
function copyJson(value) { const copied = copyJsonInner(value, { keys: 0 }, new WeakSet(), 0); return copied === INVALID || Buffer.byteLength(copied === INVALID ? '' : canonical(copied), 'utf8') > 16384 ? INVALID : copied; }

function resourcePayload(input) {
  const value = record(input, ['kind', 'locator', 'revision', 'grantBinding']);
  if (!value || !KINDS.has(value.kind) || !text(value.locator) || !DIGEST.test(value.grantBinding) || (value.revision !== null && (!Number.isSafeInteger(value.revision) || value.revision < 1 || value.revision > 2147483647))) fail(INVALID_INPUT);
  return frozen({ kind: value.kind, locator: value.locator, revision: value.revision, grantBinding: value.grantBinding });
}
function cursorPayload(input, now) {
  const value = record(input, ['requestBinding', 'grantBinding', 'continuation', 'expiresAt']);
  const continuation = value ? copyJson(value.continuation) : INVALID;
  const expires = value && typeof value.expiresAt === 'string' && value.expiresAt.length <= 64 ? Date.parse(value.expiresAt) : NaN;
  if (!value || !DIGEST.test(value.requestBinding) || !DIGEST.test(value.grantBinding) || continuation === INVALID || !Number.isFinite(expires) || expires <= now) fail(INVALID_INPUT);
  return frozen({ requestBinding: value.requestBinding, grantBinding: value.grantBinding, continuation: frozen(continuation), expiresAt: new Date(expires).toISOString() });
}
function resourceRequest(input) { const value = record(input); const keys = value && Object.keys(value).sort().join('\0'); return value && (keys === 'grantBinding\0id' || keys === 'expectedKind\0grantBinding\0id') && RESOURCE_ID.test(value.id) && DIGEST.test(value.grantBinding) && (!Object.hasOwn(value, 'expectedKind') || KINDS.has(value.expectedKind)) ? value : null; }
function cursorRequest(input) { const value = record(input, ['id', 'requestBinding', 'grantBinding']); return value && CURSOR_ID.test(value.id) && DIGEST.test(value.requestBinding) && DIGEST.test(value.grantBinding) ? value : null; }
function generatedId(prefix, factory) { const suffix = factory ? factory(prefix) : crypto.randomBytes(32).toString('base64url'); if (typeof suffix !== 'string') fail(INVALID_INPUT); const id = suffix.startsWith(prefix) ? suffix : `${prefix}${suffix}`; const valid = prefix === 'rid_' ? RESOURCE_ID.test(id) : CURSOR_ID.test(id); if (!valid) fail(INVALID_INPUT); return id; }
function timestamp(now) { return new Date(now).toISOString(); }
function decodePayload(value, validator) { const parsed = typeof value === 'string' ? (() => { try { return JSON.parse(value); } catch { return null; } })() : value; try { return validator(parsed); } catch { return null; } }
function storedTime(value) { const parsed = value instanceof Date ? value.getTime() : typeof value === 'string' ? Date.parse(value) : NaN; return Number.isFinite(parsed) ? new Date(parsed).toISOString() : null; }
function decodeResource(row) { const value = record(row, ['id', 'fingerprint', 'payload_json', 'tombstoned', 'created_at', 'tombstoned_at']); const payload = value && decodePayload(value.payload_json, resourcePayload); const createdAt = value && storedTime(value.created_at); const tombstonedAt = value?.tombstoned_at === null ? null : storedTime(value?.tombstoned_at); return value && RESOURCE_ID.test(value.id) && DIGEST.test(value.fingerprint) && typeof value.tombstoned === 'boolean' && createdAt && ((value.tombstoned && tombstonedAt) || (!value.tombstoned && value.tombstoned_at === null)) && payload && digest(payload) === value.fingerprint ? { id: value.id, fingerprint: value.fingerprint, payload, tombstoned: value.tombstoned, createdAt, tombstonedAt } : null; }
function decodeCursor(row) { const value = record(row, ['id', 'fingerprint', 'payload_json', 'expires_at', 'tombstoned', 'created_at', 'tombstoned_at']); const payload = value && decodePayload(value.payload_json, item => { const snapshot = record(item, ['requestBinding', 'grantBinding', 'continuation', 'expiresAt']); if (!snapshot || !DIGEST.test(snapshot.requestBinding) || !DIGEST.test(snapshot.grantBinding)) fail(INVALID_INPUT); const continuation = copyJson(snapshot.continuation); const expires = Date.parse(snapshot.expiresAt); if (continuation === INVALID || !Number.isFinite(expires)) fail(INVALID_INPUT); return frozen({ requestBinding: snapshot.requestBinding, grantBinding: snapshot.grantBinding, continuation: frozen(continuation), expiresAt: new Date(expires).toISOString() }); }); const createdAt = value && storedTime(value.created_at); const tombstonedAt = value?.tombstoned_at === null ? null : storedTime(value?.tombstoned_at); const expiresAt = value && storedTime(value.expires_at); return value && CURSOR_ID.test(value.id) && DIGEST.test(value.fingerprint) && typeof value.tombstoned === 'boolean' && createdAt && ((value.tombstoned && tombstonedAt) || (!value.tombstoned && value.tombstoned_at === null)) && expiresAt && payload && payload.expiresAt === expiresAt && digest(payload) === value.fingerprint ? { id: value.id, fingerprint: value.fingerprint, payload, tombstoned: value.tombstoned, createdAt, tombstonedAt } : null; }

class BaseStore {
  constructor({ idFactory, randomFactory, now } = {}) { this.idFactory = idFactory || randomFactory; this.clock = typeof now === 'function' ? now : () => Date.now(); }
  now() { const value = this.clock(); const parsed = value instanceof Date ? value.getTime() : typeof value === 'string' ? Date.parse(value) : value; if (!Number.isFinite(parsed)) fail(INVALID_INPUT); return parsed; }
  async issueResource(input) { return clean(UNAVAILABLE, async () => { const payload = resourcePayload(input); const key = digest(payload); const replay = await this._findResource(key); if (replay) return replay.tombstoned ? fail(RETIRED) : replay.id; for (let index = 0; index < MAX_RETRIES; index += 1) { const result = await this._putResource({ id: generatedId('rid_', this.idFactory), fingerprint: key, payload, createdAt: timestamp(this.now()) }); if (result?.status === 'inserted') return result.id; const found = await this._findResource(key); if (found) return found.tombstoned ? fail(RETIRED) : found.id; } fail(UNAVAILABLE); }); }
  async issueCursor(input) { return clean(UNAVAILABLE, async () => { const payload = cursorPayload(input, this.now()); const key = digest(payload); const replay = await this._findCursor(key); if (replay) return replay.tombstoned ? fail(RETIRED) : replay.id; for (let index = 0; index < MAX_RETRIES; index += 1) { const result = await this._putCursor({ id: generatedId('cur_', this.idFactory), fingerprint: key, payload, createdAt: timestamp(this.now()) }); if (result?.status === 'inserted') return result.id; const found = await this._findCursor(key); if (found) return found.tombstoned ? fail(RETIRED) : found.id; } fail(UNAVAILABLE); }); }
  async resolveResource(input) { const request = resourceRequest(input); if (!request) throw error(NOT_FOUND); try { const row = await this._getResource(request.id); if (!row || row.tombstoned || row.payload.grantBinding !== request.grantBinding || (request.expectedKind && row.payload.kind !== request.expectedKind)) throw error(NOT_FOUND); return frozen(copyJson(row.payload)); } catch { throw error(NOT_FOUND); } }
  async resolveCursor(input) { const request = cursorRequest(input); if (!request) throw error(CURSOR_INVALID); try { const row = await this._getCursor(request.id); if (!row || row.tombstoned || Date.parse(row.payload.expiresAt) <= this.now() || row.payload.requestBinding !== request.requestBinding || row.payload.grantBinding !== request.grantBinding) throw error(CURSOR_INVALID); return frozen(copyJson(row.payload.continuation)); } catch { throw error(CURSOR_INVALID); } }
  async tombstone(id) { return clean(UNAVAILABLE, async () => { if (typeof id !== 'string' || (!RESOURCE_ID.test(id) && !CURSOR_ID.test(id))) fail(INVALID_INPUT); return { tombstoned: await this._tombstone(id, timestamp(this.now())) }; }); }
  async pruneExpired(input) { return clean(UNAVAILABLE, async () => { const value = record(input, ['before', 'limit']); const before = value && typeof value.before === 'string' && value.before.length <= 64 ? Date.parse(value.before) : NaN; if (!value || !Number.isFinite(before) || !Number.isSafeInteger(value.limit) || value.limit < 1 || value.limit > 1000) fail(INVALID_INPUT); return { pruned: await this._prune(before, value.limit) }; }); }
}

export class MemoryOpaqueReferenceStore extends BaseStore {
  constructor(options = {}) { super(options); this.resources = new Map(); this.cursors = new Map(); this.resourceByFingerprint = new Map(); this.cursorByFingerprint = new Map(); }
  _resource(row) { return row ? decodeResource({ id: row.id, fingerprint: row.fingerprint, payload_json: row.payload, tombstoned: row.tombstoned, created_at: row.createdAt, tombstoned_at: row.tombstonedAt }) : null; }
  _cursor(row) { return row ? decodeCursor({ id: row.id, fingerprint: row.fingerprint, payload_json: row.payload, expires_at: row.payload?.expiresAt, tombstoned: row.tombstoned, created_at: row.createdAt, tombstoned_at: row.tombstonedAt }) : null; }
  async _findResource(key) { return this._resource(this.resourceByFingerprint.get(key)); } async _findCursor(key) { return this._cursor(this.cursorByFingerprint.get(key)); }
  async _putResource(row) { const replay = this.resourceByFingerprint.get(row.fingerprint); if (replay) return 'replay'; if (this.resources.has(row.id)) return 'collision'; const stored = { ...row, tombstoned: false, tombstonedAt: null }; this.resources.set(row.id, stored); this.resourceByFingerprint.set(row.fingerprint, stored); return { id: row.id, status: 'inserted' }; }
  async _putCursor(row) { const replay = this.cursorByFingerprint.get(row.fingerprint); if (replay) return 'replay'; if (this.cursors.has(row.id)) return 'collision'; const stored = { ...row, tombstoned: false, tombstonedAt: null }; this.cursors.set(row.id, stored); this.cursorByFingerprint.set(row.fingerprint, stored); return { id: row.id, status: 'inserted' }; }
  async _getResource(id) { return this._resource(this.resources.get(id)); } async _getCursor(id) { return this._cursor(this.cursors.get(id)); }
  async _tombstone(id, at) { const row = this.resources.get(id) || this.cursors.get(id); if (!row || row.tombstoned) return false; row.tombstoned = true; row.tombstonedAt = at; return true; }
  async _prune(before, limit) { let count = 0; for (const [id, row] of this.cursors) if (count < limit && Date.parse(row.payload.expiresAt) <= before) { this.cursors.delete(id); this.cursorByFingerprint.delete(row.fingerprint); count += 1; } return count; }
}

const SQLITE_SCHEMA = `CREATE TABLE IF NOT EXISTS capability_opaque_reference_meta_v1 (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID; CREATE TABLE IF NOT EXISTS capability_opaque_resources_v1 (id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL UNIQUE, payload_json TEXT NOT NULL, tombstoned INTEGER NOT NULL DEFAULT 0 CHECK(tombstoned IN (0,1)), created_at TEXT NOT NULL, tombstoned_at TEXT) WITHOUT ROWID; CREATE TABLE IF NOT EXISTS capability_opaque_cursors_v1 (id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL UNIQUE, payload_json TEXT NOT NULL, expires_at TEXT NOT NULL, tombstoned INTEGER NOT NULL DEFAULT 0 CHECK(tombstoned IN (0,1)), created_at TEXT NOT NULL, tombstoned_at TEXT) WITHOUT ROWID; CREATE INDEX IF NOT EXISTS capability_opaque_cursors_v1_expiry ON capability_opaque_cursors_v1(expires_at);`;
export class SqliteOpaqueReferenceStore extends BaseStore {
  constructor({ filename = ':memory:', database, ...options } = {}) { super(options); this.db = database || new Database(filename); this.db.exec(SQLITE_SCHEMA); this.db.prepare("INSERT INTO capability_opaque_reference_meta_v1(key,value) VALUES('schema_version',?) ON CONFLICT(key) DO NOTHING").run(String(CAPABILITY_OPAQUE_REFERENCE_SCHEMA_VERSION)); if (this.db.prepare("SELECT value FROM capability_opaque_reference_meta_v1 WHERE key='schema_version'").get()?.value !== String(CAPABILITY_OPAQUE_REFERENCE_SCHEMA_VERSION)) fail(INVALID_INPUT); }
  _resource(row) { const normalized = row && { ...row, tombstoned: Boolean(row.tombstoned) }; return decodeResource(normalized); } _cursor(row) { const normalized = row && { ...row, tombstoned: Boolean(row.tombstoned) }; return decodeCursor(normalized); }
  async _findResource(key) { return this._resource(this.db.prepare('SELECT * FROM capability_opaque_resources_v1 WHERE fingerprint=?').get(key)); } async _findCursor(key) { return this._cursor(this.db.prepare('SELECT * FROM capability_opaque_cursors_v1 WHERE fingerprint=?').get(key)); }
  async _putResource(row) { const out = this.db.prepare('INSERT INTO capability_opaque_resources_v1(id,fingerprint,payload_json,created_at) VALUES(?,?,?,?) ON CONFLICT DO NOTHING').run(row.id, row.fingerprint, JSON.stringify(row.payload), row.createdAt); return out.changes ? { id: row.id, status: 'inserted' } : 'collision'; }
  async _putCursor(row) { const out = this.db.prepare('INSERT INTO capability_opaque_cursors_v1(id,fingerprint,payload_json,expires_at,created_at) VALUES(?,?,?,?,?) ON CONFLICT DO NOTHING').run(row.id, row.fingerprint, JSON.stringify(row.payload), row.payload.expiresAt, row.createdAt); return out.changes ? { id: row.id, status: 'inserted' } : 'collision'; }
  async _getResource(id) { return this._resource(this.db.prepare('SELECT * FROM capability_opaque_resources_v1 WHERE id=?').get(id)); } async _getCursor(id) { return this._cursor(this.db.prepare('SELECT * FROM capability_opaque_cursors_v1 WHERE id=?').get(id)); }
  async _tombstone(id, at) { const table = RESOURCE_ID.test(id) ? 'capability_opaque_resources_v1' : 'capability_opaque_cursors_v1'; return this.db.prepare(`UPDATE ${table} SET tombstoned=1,tombstoned_at=? WHERE id=? AND tombstoned=0`).run(at, id).changes === 1; }
  async _prune(before, limit) { const rows = this.db.prepare('SELECT id FROM capability_opaque_cursors_v1 WHERE expires_at<=? ORDER BY expires_at,id LIMIT ?').all(timestamp(before), limit); const remove = this.db.prepare('DELETE FROM capability_opaque_cursors_v1 WHERE id=?'); this.db.transaction(() => rows.forEach(row => remove.run(row.id)))(); return rows.length; }
  close() { this.db.close(); }
}

const PG_SCHEMA = `CREATE TABLE IF NOT EXISTS capability_opaque_reference_meta_v1 (key text PRIMARY KEY, value text NOT NULL); CREATE TABLE IF NOT EXISTS capability_opaque_resources_v1 (id text PRIMARY KEY, fingerprint text NOT NULL UNIQUE, payload_json jsonb NOT NULL, tombstoned boolean NOT NULL DEFAULT false, created_at timestamptz NOT NULL, tombstoned_at timestamptz); CREATE TABLE IF NOT EXISTS capability_opaque_cursors_v1 (id text PRIMARY KEY, fingerprint text NOT NULL UNIQUE, payload_json jsonb NOT NULL, expires_at timestamptz NOT NULL, tombstoned boolean NOT NULL DEFAULT false, created_at timestamptz NOT NULL, tombstoned_at timestamptz); CREATE INDEX IF NOT EXISTS capability_opaque_cursors_v1_expiry ON capability_opaque_cursors_v1(expires_at);`;
export class PostgresOpaqueReferenceStore extends BaseStore {
  constructor({ pool, poolFactory, connectionString, ...options } = {}) { super(options); this.pool = pool || (poolFactory ? poolFactory({ connectionString }) : new Pool({ connectionString })); if (!this.pool || typeof this.pool.query !== 'function') fail(INVALID_INPUT); this.initialized = null; }
  async ready() { if (!this.initialized) { this.initialized = (async () => { await this.pool.query(PG_SCHEMA); await this.pool.query("INSERT INTO capability_opaque_reference_meta_v1(key,value) VALUES('schema_version',$1) ON CONFLICT(key) DO NOTHING", [String(CAPABILITY_OPAQUE_REFERENCE_SCHEMA_VERSION)]); const row = await this.pool.query("SELECT value FROM capability_opaque_reference_meta_v1 WHERE key='schema_version'"); if (row.rows?.[0]?.value !== String(CAPABILITY_OPAQUE_REFERENCE_SCHEMA_VERSION)) fail(UNAVAILABLE); })(); try { await this.initialized; } catch (cause) { this.initialized = null; throw cause; } } return this.initialized; }
  async query(sql, values = []) { await this.ready(); return this.pool.query(sql, values); }
  async _findResource(key) { return decodeResource((await this.query('SELECT * FROM capability_opaque_resources_v1 WHERE fingerprint=$1', [key])).rows?.[0]); } async _findCursor(key) { return decodeCursor((await this.query('SELECT * FROM capability_opaque_cursors_v1 WHERE fingerprint=$1', [key])).rows?.[0]); }
  async _putResource(row) { const out = await this.query('INSERT INTO capability_opaque_resources_v1(id,fingerprint,payload_json,created_at) VALUES($1,$2,$3::jsonb,$4) ON CONFLICT DO NOTHING RETURNING id', [row.id, row.fingerprint, JSON.stringify(row.payload), row.createdAt]); return out.rows?.length ? { id: row.id, status: 'inserted' } : 'collision'; }
  async _putCursor(row) { const out = await this.query('INSERT INTO capability_opaque_cursors_v1(id,fingerprint,payload_json,expires_at,created_at) VALUES($1,$2,$3::jsonb,$4,$5) ON CONFLICT DO NOTHING RETURNING id', [row.id, row.fingerprint, JSON.stringify(row.payload), row.payload.expiresAt, row.createdAt]); return out.rows?.length ? { id: row.id, status: 'inserted' } : 'collision'; }
  async _getResource(id) { return decodeResource((await this.query('SELECT * FROM capability_opaque_resources_v1 WHERE id=$1', [id])).rows?.[0]); } async _getCursor(id) { return decodeCursor((await this.query('SELECT * FROM capability_opaque_cursors_v1 WHERE id=$1', [id])).rows?.[0]); }
  async _tombstone(id, at) { const table = RESOURCE_ID.test(id) ? 'capability_opaque_resources_v1' : 'capability_opaque_cursors_v1'; return Boolean((await this.query(`UPDATE ${table} SET tombstoned=true,tombstoned_at=$1 WHERE id=$2 AND tombstoned=false RETURNING id`, [at, id])).rows?.length); }
  async _prune(before, limit) { return (await this.query('DELETE FROM capability_opaque_cursors_v1 WHERE id IN (SELECT id FROM capability_opaque_cursors_v1 WHERE expires_at <= $1 ORDER BY expires_at,id LIMIT $2) RETURNING id', [timestamp(before), limit])).rows?.length || 0; }
  async close() { if (typeof this.pool.end === 'function') await this.pool.end(); }
}
