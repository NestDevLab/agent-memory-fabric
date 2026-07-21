import crypto from 'node:crypto';
import Database from 'better-sqlite3';
import pg from 'pg';

import { isConversationEventUtcTimestamp, validateConversationEvent } from './conversation-event-v3.mjs';
import { canonicalJson } from './ingest/transcripts/canonical.mjs';

const { Pool } = pg;
const EVENT_ID = /^cevt_[a-z0-9][a-z0-9_-]{7,127}$/;
const CONVERSATION_ID = /^ccon_[a-z0-9][a-z0-9_-]{7,127}$/;
const IDEMPOTENCY_KEY = /^cai_[a-z0-9][a-z0-9_-]{7,127}$/;
const ORDERING_VERSION = 'conversation-archive-order/v1';
// The v1 cursor envelope is at most 519 canonical UTF-8 bytes with every opaque
// identifier at its schema maximum. Keep a small fixed framing margin, then
// derive the base64url cap rather than accepting an unbounded encoded string.
const CURSOR_MAX_BYTES = 544;
const CURSOR_MAX_BODY_LENGTH = Math.ceil((CURSOR_MAX_BYTES * 4) / 3);

class AuditUnavailableError extends Error {}

function result(outcome, extra = {}) { return { outcome, stateChanged: false, items: [], nextCursor: null, ...extra }; }
function invalid() { return result('request_invalid'); }
function projection(row) {
  return { eventId: row.event_id, conversationId: row.conversation_id, logicalDigest: row.logical_digest,
    payloadDigest: row.payload_digest, sourceOccurredAt: row.source_occurred_at,
    sourceSequence: Number(row.source_sequence), state: row.state };
}
function timestampKey(value) {
  const match = /^(.{19})(?:\.([0-9]{1,9}))?Z$/.exec(value);
  return match ? `${match[1]}.${(match[2] ?? '').padEnd(9, '0')}` : null;
}
function strictTimestamp(value) { return isConversationEventUtcTimestamp(value) ? timestampKey(value) : null; }
function requestDigest(value) { return crypto.createHash('sha256').update(canonicalJson(value)).digest('hex'); }
function archiveRequestDigest(operation, idempotencyKey, event) { return requestDigest({ operation, idempotencyKey, eventId: event.eventId, payloadDigest: event.integrity.payloadDigest }); }
function requireCursorKey(cursorKey) {
  if (!Buffer.isBuffer(cursorKey) || cursorKey.length < 32) throw new TypeError('conversation_archive_cursor_key_invalid');
  return cursorKey;
}
function requireFunction(value, code) { if (typeof value !== 'function') throw new TypeError(code); return value; }
function cursorMac(value, cursorKey) { return crypto.createHmac('sha256', cursorKey).update(canonicalJson(value)).digest('base64url'); }
function safeEqualText(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') return false;
  const a = Buffer.from(left, 'utf8'); const b = Buffer.from(right, 'utf8');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function encodeCursor(binding, row, cursorKey) {
  const unsigned = { v: 1, binding, state: { t: row.source_time_key, s: Number(row.source_sequence), e: row.event_id } };
  return `car_${Buffer.from(canonicalJson({ ...unsigned, mac: cursorMac(unsigned, cursorKey) })).toString('base64url')}`;
}
function decodeCursor(cursor, binding, cursorKey) {
  if (typeof cursor !== 'string' || !new RegExp(`^car_[A-Za-z0-9_-]{16,${CURSOR_MAX_BODY_LENGTH}}$`).test(cursor)) return null;
  try {
    const bytes = Buffer.from(cursor.slice(4), 'base64url');
    if (bytes.length < 16 || bytes.length > CURSOR_MAX_BYTES) return null;
    const value = JSON.parse(bytes.toString('utf8'));
    const unsigned = { v: value.v, binding: value.binding, state: value.state };
    if (value.v !== 1 || canonicalJson(value.binding) !== canonicalJson(binding) ||
      !value.state || typeof value.state.t !== 'string' || !Number.isSafeInteger(value.state.s) ||
      !EVENT_ID.test(value.state.e) || !safeEqualText(value.mac, cursorMac(unsigned, cursorKey))) return null;
    return value.state;
  } catch { return null; }
}
function validateWrite(event, idempotencyKey, operation, resolveIntegrityKey) {
  if (!IDEMPOTENCY_KEY.test(idempotencyKey)) return null;
  try {
    const verified = validateConversationEvent(event, { resolveIntegrityKey });
    if ((operation === 'tombstone') !== (verified.state === 'tombstone')) return null;
    return verified;
  } catch { return null; }
}
function eventRow(event, expiresAt) {
  const sourceTimeKey = strictTimestamp(event.sourceOccurredAt);
  if (!sourceTimeKey || !strictTimestamp(expiresAt)) return null;
  return { eventId: event.eventId, conversationId: event.conversationId, sourceInstanceId: event.sourceInstanceId,
    state: event.state, logicalDigest: event.logicalDigest, payloadDigest: event.integrity.payloadDigest,
    sourceOccurredAt: event.sourceOccurredAt, sourceTimeKey, sourceSequence: event.ordering.sourceSequence,
    expiresAt, expiresTimeKey: timestampKey(expiresAt), eventJson: canonicalJson(event) };
}
function validExpiresAt(value) { return typeof value === 'string' && strictTimestamp(value) ? value : null; }
function references(event) { return [event.replacesEventId, event.tombstonesEventId, ...(event.conflictsWithEventIds ?? [])].filter(Boolean); }
function conflict(existing, event) {
  return result('conflict_visible', { conflict: { eventId: event.eventId, logicalDigest: event.logicalDigest,
    existingPayloadDigest: existing.payload_digest, receivedPayloadDigest: event.integrity.payloadDigest } });
}
function listRequest(conversationId, limit, includeTombstones, cursor, cursorKey) {
  if (!CONVERSATION_ID.test(conversationId) || !Number.isSafeInteger(limit) || limit < 1 || limit > 100 ||
      typeof includeTombstones !== 'boolean' || (cursor !== undefined && typeof cursor !== 'string')) return null;
  const binding = { conversationId, includeTombstones, orderingVersion: ORDERING_VERSION, limit };
  return { binding, state: cursor === undefined ? null : decodeCursor(cursor, binding, cursorKey) };
}
function expiresAtFor(event, resolveExpiresAt) {
  try { return validExpiresAt(resolveExpiresAt(event)); } catch { return null; }
}

const SQLITE_DDL = `
PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;
CREATE TABLE IF NOT EXISTS conversation_archive_events_v1 (
 event_id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL, source_instance_id TEXT NOT NULL, state TEXT NOT NULL,
 logical_digest TEXT NOT NULL, payload_digest TEXT NOT NULL, source_occurred_at TEXT NOT NULL, source_time_key TEXT NOT NULL,
 source_sequence INTEGER NOT NULL, expires_at TEXT NOT NULL, expires_time_key TEXT NOT NULL, event_json TEXT NOT NULL, expired INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS conversation_archive_events_v1_list ON conversation_archive_events_v1(conversation_id, source_time_key, source_sequence, event_id);
CREATE TABLE IF NOT EXISTS conversation_archive_requests_v1 (idempotency_key TEXT PRIMARY KEY, request_digest TEXT NOT NULL, outcome TEXT NOT NULL, operation TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS conversation_archive_conflicts_v1 (id INTEGER PRIMARY KEY, event_id TEXT NOT NULL, existing_payload_digest TEXT NOT NULL, received_payload_digest TEXT NOT NULL, evidence_json TEXT NOT NULL, UNIQUE(event_id, received_payload_digest));
CREATE TABLE IF NOT EXISTS conversation_archive_audit_v1 (id INTEGER PRIMARY KEY, action TEXT NOT NULL, outcome TEXT NOT NULL, event_id TEXT, created_at TEXT NOT NULL);
`;

export class SqliteConversationArchive {
  constructor({ filename = ':memory:', resolveIntegrityKey, resolveExpiresAt, cursorKey, fault } = {}) {
    const checkedCursorKey = requireCursorKey(cursorKey);
    const checkedIntegrityKey = requireFunction(resolveIntegrityKey, 'conversation_archive_integrity_key_resolver_invalid');
    const checkedExpiresAt = requireFunction(resolveExpiresAt, 'conversation_archive_expiry_resolver_invalid');
    this.db = new Database(filename); this.resolveIntegrityKey = checkedIntegrityKey; this.resolveExpiresAt = checkedExpiresAt;
    this.cursorKey = checkedCursorKey; this.fault = fault; this.db.exec(SQLITE_DDL); this.writeTransaction = this.db.transaction((operation, event, key) => this._write(operation, event, key));
  }
  _audit(action, outcome, eventId = null) {
    if (this.fault?.audit) throw new AuditUnavailableError('audit_unavailable');
    try { this.db.prepare('INSERT INTO conversation_archive_audit_v1(action,outcome,event_id,created_at) VALUES (?,?,?,?)').run(action, outcome, eventId, new Date().toISOString()); }
    catch (error) { throw new AuditUnavailableError('audit_unavailable', { cause: error }); }
  }
  _write(operation, event, idempotencyKey) {
    const verified = validateWrite(event, idempotencyKey, operation, this.resolveIntegrityKey); if (!verified) return invalid();
    const digest = archiveRequestDigest(operation, idempotencyKey, verified);
    const replay = this.db.prepare('SELECT * FROM conversation_archive_requests_v1 WHERE idempotency_key=?').get(idempotencyKey);
    if (replay) {
      if (replay.request_digest === digest) { this._audit(operation, 'recorded', verified.eventId); return result('duplicate'); }
      const existing = this.db.prepare('SELECT * FROM conversation_archive_events_v1 WHERE event_id=?').get(verified.eventId);
      if (existing) { this._recordConflict(operation, existing, verified, idempotencyKey, digest); return conflict(existing, verified); }
      return invalid();
    }
    const existing = this.db.prepare('SELECT * FROM conversation_archive_events_v1 WHERE event_id=?').get(verified.eventId);
    if (existing) { this._recordConflict(operation, existing, verified, idempotencyKey, digest); return conflict(existing, verified); }
    const targets = references(verified);
    for (const target of targets) {
      const found = this.db.prepare('SELECT conversation_id,source_instance_id FROM conversation_archive_events_v1 WHERE event_id=?').get(target);
      if (!found || found.conversation_id !== verified.conversationId || found.source_instance_id !== verified.sourceInstanceId) return invalid();
    }
    const row = eventRow(verified, expiresAtFor(verified, this.resolveExpiresAt)); if (!row) return invalid();
    if (this.fault?.transaction) throw new Error('transaction');
    this.db.prepare(`INSERT INTO conversation_archive_events_v1(event_id,conversation_id,source_instance_id,state,logical_digest,payload_digest,source_occurred_at,source_time_key,source_sequence,expires_at,expires_time_key,event_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`).run(row.eventId,row.conversationId,row.sourceInstanceId,row.state,row.logicalDigest,row.payloadDigest,row.sourceOccurredAt,row.sourceTimeKey,row.sourceSequence,row.expiresAt,row.expiresTimeKey,row.eventJson);
    this.db.prepare('INSERT INTO conversation_archive_requests_v1(idempotency_key,request_digest,outcome,operation) VALUES (?,?,?,?)').run(idempotencyKey,digest,'stored',operation);
    this._audit(operation, 'recorded', row.eventId); return result('stored', { stateChanged: true });
  }
  _recordConflict(operation, existing, verified, idempotencyKey, digest) {
    this.db.prepare('INSERT OR IGNORE INTO conversation_archive_conflicts_v1(event_id,existing_payload_digest,received_payload_digest,evidence_json) VALUES (?,?,?,?)').run(verified.eventId, existing.payload_digest, verified.integrity.payloadDigest, canonicalJson(verified));
    this.db.prepare('INSERT OR IGNORE INTO conversation_archive_requests_v1(idempotency_key,request_digest,outcome,operation) VALUES (?,?,?,?)').run(idempotencyKey,digest,'conflict_visible',operation);
    this._audit(operation, 'recorded', verified.eventId);
  }
  append(event, idempotencyKey) { try { return this.writeTransaction('append', event, idempotencyKey); } catch (error) { return result(error instanceof AuditUnavailableError ? 'audit_unavailable' : 'transaction_rolled_back'); } }
  tombstone(event, idempotencyKey) { try { return this.writeTransaction('tombstone', event, idempotencyKey); } catch (error) { return result(error instanceof AuditUnavailableError ? 'audit_unavailable' : 'transaction_rolled_back'); } }
  list(conversationId, limit, includeTombstones, cursor) {
    const request = listRequest(conversationId, limit, includeTombstones, cursor, this.cursorKey); if (!request) return invalid(); if (cursor !== undefined && !request.state) return result('cursor_binding_invalid');
    const clauses = ['e.conversation_id=?', 'e.expired=0', "e.state <> 'conflict'", `NOT EXISTS (
      SELECT 1 FROM conversation_archive_events_v1 t
      WHERE t.conversation_id=e.conversation_id AND (
        (t.state='tombstone' AND json_extract(t.event_json,'$.tombstonesEventId')=e.event_id) OR
        (t.state IN ('edited','replacement') AND json_extract(t.event_json,'$.replacesEventId')=e.event_id)
      )
    )`]; const values = [conversationId];
    if (!includeTombstones) clauses.push("e.state <> 'tombstone'");
    if (request.state) { clauses.push('(e.source_time_key > ? OR (e.source_time_key = ? AND (e.source_sequence > ? OR (e.source_sequence = ? AND e.event_id > ?))))'); values.push(request.state.t,request.state.t,request.state.s,request.state.s,request.state.e); }
    const rows = this.db.prepare(`SELECT e.* FROM conversation_archive_events_v1 e WHERE ${clauses.join(' AND ')} ORDER BY e.source_time_key,e.source_sequence,e.event_id LIMIT ?`).all(...values,limit + 1);
    const page = rows.slice(0, limit); return result('listed', { items: page.map(projection), nextCursor: rows.length > limit ? encodeCursor(request.binding, page.at(-1), this.cursorKey) : null });
  }
  applyRetention(cutoff, limit, idempotencyKey) {
    if (!strictTimestamp(cutoff) || !Number.isSafeInteger(limit) || limit < 1 || limit > 1000 || !IDEMPOTENCY_KEY.test(idempotencyKey)) return invalid();
    try { return this.db.transaction(() => {
      const digest = requestDigest({ operation: 'apply_retention', cutoff, limit, idempotencyKey }); const replay = this.db.prepare('SELECT * FROM conversation_archive_requests_v1 WHERE idempotency_key=?').get(idempotencyKey);
      if (replay) {
        if (replay.request_digest !== digest) return invalid();
        this._audit('apply_retention', 'recorded');
        return result('duplicate');
      }
      if (this.fault?.transaction) throw new Error('transaction');
      const rows = this.db.prepare(`SELECT e.event_id FROM conversation_archive_events_v1 e WHERE e.expired=0 AND e.expires_time_key<=? AND e.state<>'conflict' AND NOT EXISTS (SELECT 1 FROM conversation_archive_conflicts_v1 c WHERE c.event_id=e.event_id) ORDER BY e.expires_time_key,e.source_time_key,e.source_sequence,e.event_id LIMIT ?`).all(timestampKey(cutoff),limit);
      if (rows.length) this.db.prepare(`UPDATE conversation_archive_events_v1 SET expired=1 WHERE event_id IN (${rows.map(() => '?').join(',')})`).run(...rows.map(row => row.event_id));
      this.db.prepare('INSERT INTO conversation_archive_requests_v1(idempotency_key,request_digest,outcome,operation) VALUES (?,?,?,?)').run(idempotencyKey,digest,'retention_expired','apply_retention'); this._audit('apply_retention','recorded');
      return result('retention_expired',{stateChanged:true});
    })(); } catch (error) { return result(error instanceof AuditUnavailableError ? 'audit_unavailable' : 'transaction_rolled_back'); }
  }
  auditRows() { return this.db.prepare('SELECT action,outcome,event_id FROM conversation_archive_audit_v1 ORDER BY id').all(); }
  conflictEvidenceCount() { return this.db.prepare('SELECT count(*) AS count FROM conversation_archive_conflicts_v1').get().count; }
  close() { this.db.close(); }
}

const POSTGRES_DDL = `
CREATE SCHEMA IF NOT EXISTS agent_memory_fabric;
CREATE TABLE IF NOT EXISTS agent_memory_fabric.conversation_archive_events_v1 (event_id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL, source_instance_id TEXT NOT NULL, state TEXT NOT NULL, logical_digest TEXT NOT NULL, payload_digest TEXT NOT NULL, source_occurred_at TEXT NOT NULL, source_time_key TEXT NOT NULL, source_sequence BIGINT NOT NULL, expires_at TEXT NOT NULL, expires_time_key TEXT NOT NULL, event_json JSONB NOT NULL, expired BOOLEAN NOT NULL DEFAULT false);
CREATE INDEX IF NOT EXISTS conversation_archive_events_v1_list ON agent_memory_fabric.conversation_archive_events_v1(conversation_id,source_time_key,source_sequence,event_id);
CREATE TABLE IF NOT EXISTS agent_memory_fabric.conversation_archive_requests_v1 (idempotency_key TEXT PRIMARY KEY, request_digest TEXT NOT NULL, outcome TEXT NOT NULL, operation TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS agent_memory_fabric.conversation_archive_conflicts_v1 (id BIGSERIAL PRIMARY KEY,event_id TEXT NOT NULL,existing_payload_digest TEXT NOT NULL,received_payload_digest TEXT NOT NULL,evidence_json JSONB NOT NULL,UNIQUE(event_id,received_payload_digest));
CREATE TABLE IF NOT EXISTS agent_memory_fabric.conversation_archive_audit_v1 (id BIGSERIAL PRIMARY KEY,action TEXT NOT NULL,outcome TEXT NOT NULL,event_id TEXT,created_at TIMESTAMPTZ NOT NULL);
`;

export class PostgresConversationArchive {
  constructor({ pool, connectionString, poolFactory = config => new Pool(config), resolveIntegrityKey, resolveExpiresAt, cursorKey, fault } = {}) {
    const checkedCursorKey = requireCursorKey(cursorKey);
    const checkedIntegrityKey = requireFunction(resolveIntegrityKey, 'conversation_archive_integrity_key_resolver_invalid');
    const checkedExpiresAt = requireFunction(resolveExpiresAt, 'conversation_archive_expiry_resolver_invalid');
    this.pool = pool || poolFactory({ connectionString }); this.resolveIntegrityKey = checkedIntegrityKey;
    this.resolveExpiresAt = checkedExpiresAt; this.cursorKey = checkedCursorKey; this.fault = fault;
    this.initialized = null;
  }
  async ready() {
    if (!this.initialized) {
      const attempt = Promise.resolve().then(() => this.pool.query(POSTGRES_DDL));
      const shared = attempt.catch(error => {
        if (this.initialized === shared) this.initialized = null;
        throw error;
      });
      this.initialized = shared;
    }
    await this.initialized;
    return this;
  }
  async _audit(client, action, eventId = null) {
    if (this.fault?.audit) throw new AuditUnavailableError('audit_unavailable');
    try { await client.query('INSERT INTO agent_memory_fabric.conversation_archive_audit_v1(action,outcome,event_id,created_at) VALUES ($1,$2,$3,now())', [action, 'recorded', eventId]); }
    catch (error) { throw new AuditUnavailableError('audit_unavailable', { cause: error }); }
  }
  async _lock(client, keys) { for (const key of keys.sort()) await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [key]); }
  async _committedWriteOutcome(idempotencyKey, digest, event) {
    const row = (await this.pool.query('SELECT request_digest,outcome FROM agent_memory_fabric.conversation_archive_requests_v1 WHERE idempotency_key=$1', [idempotencyKey])).rows[0];
    if (!row || row.request_digest !== digest) return null;
    if (row.outcome !== 'conflict_visible') return result('duplicate');
    const existing = (await this.pool.query('SELECT * FROM agent_memory_fabric.conversation_archive_events_v1 WHERE event_id=$1', [event.eventId])).rows[0];
    return existing ? conflict(existing, event) : null;
  }
  async _committedRetentionOutcome(idempotencyKey, digest) {
    const row = (await this.pool.query('SELECT request_digest,outcome,operation FROM agent_memory_fabric.conversation_archive_requests_v1 WHERE idempotency_key=$1', [idempotencyKey])).rows[0];
    if (row?.request_digest !== digest || row.outcome !== 'retention_expired' || row.operation !== 'apply_retention') return null;
    return result('duplicate');
  }
  async _referencesAreLocal(client, event) {
    const targets = references(event); if (!targets.length) return true;
    const rows = (await client.query('SELECT conversation_id,source_instance_id FROM agent_memory_fabric.conversation_archive_events_v1 WHERE event_id=ANY($1::text[])', [targets])).rows;
    return rows.length === targets.length && rows.every(row => row.conversation_id === event.conversationId && row.source_instance_id === event.sourceInstanceId);
  }
  async _storeConflict(client, operation, existing, event, idempotencyKey, digest) {
    await client.query('INSERT INTO agent_memory_fabric.conversation_archive_conflicts_v1(event_id,existing_payload_digest,received_payload_digest,evidence_json) VALUES ($1,$2,$3,$4::jsonb) ON CONFLICT DO NOTHING', [event.eventId, existing.payload_digest, event.integrity.payloadDigest, canonicalJson(event)]);
    await client.query('INSERT INTO agent_memory_fabric.conversation_archive_requests_v1(idempotency_key,request_digest,outcome,operation) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING', [idempotencyKey, digest, 'conflict_visible', operation]);
    await this._audit(client, operation, event.eventId);
    return conflict(existing, event);
  }
  async _write(operation, event, idempotencyKey) {
    const verified = validateWrite(event, idempotencyKey, operation, this.resolveIntegrityKey);
    if (!verified) return invalid(); await this.ready();
    const digest = archiveRequestDigest(operation, idempotencyKey, verified); let client = await this.pool.connect();
    try {
      await client.query('BEGIN'); await this._lock(client, [`archive:event:${verified.eventId}`, `archive:idempotency:${idempotencyKey}`]);
      const replay = (await client.query('SELECT * FROM agent_memory_fabric.conversation_archive_requests_v1 WHERE idempotency_key=$1', [idempotencyKey])).rows[0];
      const existing = (await client.query('SELECT * FROM agent_memory_fabric.conversation_archive_events_v1 WHERE event_id=$1', [verified.eventId])).rows[0];
      if (replay?.request_digest === digest) { await this._audit(client, operation, verified.eventId); await client.query('COMMIT'); return result('duplicate'); }
      if (replay || existing) {
        if (!existing) { await client.query('ROLLBACK'); return invalid(); }
        const response = await this._storeConflict(client, operation, existing, verified, idempotencyKey, digest);
        await client.query('COMMIT'); return response;
      }
      if (!(await this._referencesAreLocal(client, verified))) { await client.query('ROLLBACK'); return invalid(); }
      const row = eventRow(verified, expiresAtFor(verified, this.resolveExpiresAt));
      if (!row) { await client.query('ROLLBACK'); return invalid(); }
      if (this.fault?.transaction) throw new Error('transaction');
      await client.query('INSERT INTO agent_memory_fabric.conversation_archive_events_v1(event_id,conversation_id,source_instance_id,state,logical_digest,payload_digest,source_occurred_at,source_time_key,source_sequence,expires_at,expires_time_key,event_json) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb)', [row.eventId,row.conversationId,row.sourceInstanceId,row.state,row.logicalDigest,row.payloadDigest,row.sourceOccurredAt,row.sourceTimeKey,row.sourceSequence,row.expiresAt,row.expiresTimeKey,row.eventJson]);
      await client.query('INSERT INTO agent_memory_fabric.conversation_archive_requests_v1(idempotency_key,request_digest,outcome,operation) VALUES ($1,$2,$3,$4)', [idempotencyKey, digest, 'stored', operation]);
      await this._audit(client, operation, row.eventId); await client.query('COMMIT'); return result('stored', { stateChanged: true });
    } catch (error) {
      try { await client.query('ROLLBACK'); } catch {}
      if (error instanceof AuditUnavailableError) return result('audit_unavailable');
      client.release(); client = null;
      return (await this._committedWriteOutcome(idempotencyKey, digest, verified).catch(() => null)) ?? result('transaction_rolled_back');
    } finally { client?.release(); }
  }
  async append(event, key) { try { return await this._write('append', event, key); } catch { return result('transaction_rolled_back'); } }
  async tombstone(event, key) { try { return await this._write('tombstone', event, key); } catch { return result('transaction_rolled_back'); } }
  async list(conversationId, limit, includeTombstones, cursor) {
    const request = listRequest(conversationId, limit, includeTombstones, cursor, this.cursorKey);
    if (!request) return invalid(); if (cursor !== undefined && !request.state) return result('cursor_binding_invalid');
    try {
      await this.ready();
      const filters = ['e.conversation_id=$1', 'e.expired=false', "e.state <> 'conflict'",
      "NOT EXISTS (SELECT 1 FROM agent_memory_fabric.conversation_archive_events_v1 t WHERE t.conversation_id=e.conversation_id AND ((t.state='tombstone' AND t.event_json->>'tombstonesEventId'=e.event_id) OR (t.state IN ('edited','replacement') AND t.event_json->>'replacesEventId'=e.event_id)))"];
    const values = [conversationId];
    if (!includeTombstones) filters.push("e.state <> 'tombstone'");
    if (request.state) {
      values.push(request.state.t, request.state.s, request.state.e);
      filters.push(`(e.source_time_key,e.source_sequence,e.event_id) > ($${values.length - 2},$${values.length - 1},$${values.length})`);
    }
    values.push(limit + 1);
    const sql = `SELECT e.* FROM agent_memory_fabric.conversation_archive_events_v1 e WHERE ${filters.join(' AND ')} ORDER BY e.source_time_key,e.source_sequence,e.event_id LIMIT $${values.length}`;
      const rows = (await this.pool.query(sql, values)).rows; const page = rows.slice(0, limit);
      return result('listed', { items: page.map(projection), nextCursor: rows.length > limit ? encodeCursor(request.binding, page.at(-1), this.cursorKey) : null });
    } catch { return result('transaction_rolled_back'); }
  }
  async applyRetention(cutoff, limit, idempotencyKey) {
    if (!strictTimestamp(cutoff) || !Number.isSafeInteger(limit) || limit < 1 || limit > 1000 || !IDEMPOTENCY_KEY.test(idempotencyKey)) return invalid();
    const digest = requestDigest({ operation: 'apply_retention', cutoff, limit, idempotencyKey }); let client = null;
    try {
      await this.ready();
      client = await this.pool.connect();
      await client.query('BEGIN'); await this._lock(client, [`archive:retention:${idempotencyKey}`]);
      const replay = (await client.query('SELECT * FROM agent_memory_fabric.conversation_archive_requests_v1 WHERE idempotency_key=$1', [idempotencyKey])).rows[0];
      if (replay) {
        if (replay.request_digest !== digest) { await client.query('ROLLBACK'); return invalid(); }
        await this._audit(client, 'apply_retention');
        await client.query('COMMIT');
        return result('duplicate');
      }
      if (this.fault?.transaction) throw new Error('transaction');
      await client.query(`WITH eligible AS (SELECT e.event_id FROM agent_memory_fabric.conversation_archive_events_v1 e WHERE e.expired=false AND e.expires_time_key<=$1 AND e.state<>'conflict' AND NOT EXISTS (SELECT 1 FROM agent_memory_fabric.conversation_archive_conflicts_v1 c WHERE c.event_id=e.event_id) ORDER BY e.expires_time_key,e.source_time_key,e.source_sequence,e.event_id LIMIT $2 FOR UPDATE) UPDATE agent_memory_fabric.conversation_archive_events_v1 e SET expired=true FROM eligible WHERE e.event_id=eligible.event_id`, [timestampKey(cutoff), limit]);
      await client.query('INSERT INTO agent_memory_fabric.conversation_archive_requests_v1(idempotency_key,request_digest,outcome,operation) VALUES ($1,$2,$3,$4)', [idempotencyKey, digest, 'retention_expired', 'apply_retention']);
      await this._audit(client, 'apply_retention'); await client.query('COMMIT'); return result('retention_expired', { stateChanged: true });
    } catch (error) {
      try { await client?.query('ROLLBACK'); } catch {}
      if (error instanceof AuditUnavailableError) return result('audit_unavailable');
      client?.release(); client = null;
      return (await this._committedRetentionOutcome(idempotencyKey, digest).catch(() => null)) ?? result('transaction_rolled_back');
    } finally { client?.release(); }
  }
  async auditRows() { await this.ready(); return (await this.pool.query('SELECT action,outcome,event_id FROM agent_memory_fabric.conversation_archive_audit_v1 ORDER BY id')).rows; }
  async conflictEvidenceCount() { await this.ready(); return Number((await this.pool.query('SELECT count(*) AS count FROM agent_memory_fabric.conversation_archive_conflicts_v1')).rows[0].count); }
  async close() { await this.pool.end(); }
}
