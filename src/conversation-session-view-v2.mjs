import crypto from 'node:crypto';

import { exactContextIntersection, normalizeOpaqueTagMap } from './access-contract.mjs';
import { canonicalJson } from './ingest/transcripts/canonical.mjs';

const CONVERSATION_ID = /^ccon_[a-z0-9][a-z0-9_-]{7,127}$/;
const EVENT_ID = /^cevt_[a-z0-9][a-z0-9_-]{7,127}$/;
const ORDER_KEY = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{9}$/;
const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$/;
const MAX_CONTENT_CODE_POINTS = 4096;
const MAX_CURSOR_CHARS = 512;
const MAX_CURSOR_BODY_CHARS = MAX_CURSOR_CHARS - 4;
const MAX_SCAN_LIMIT = 500;

function failure(code, status) {
  const error = new Error(code);
  error.status = status;
  return error;
}

function requireCursorKey(value) {
  if (!Buffer.isBuffer(value) || value.length < 32) throw new TypeError('conversation_session_view_cursor_key_invalid');
  return value;
}

function truncateText(value) {
  return Array.from(String(value ?? '')).slice(0, MAX_CONTENT_CODE_POINTS).join('');
}

function daysInMonth(year, month) {
  return month === 2 ? (year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0) ? 29 : 28) : [4, 6, 9, 11].includes(month) ? 30 : 31;
}

function parseRfc3339(value) {
  const match = RFC3339.exec(String(value));
  if (!match) return null;
  const [, yearText, monthText, dayText, hourText, minuteText, secondText, fraction = '', zone] = match;
  const year = Number(yearText); const month = Number(monthText); const day = Number(dayText);
  const hour = Number(hourText); const minute = Number(minuteText); const second = Number(secondText);
  if (month < 1 || month > 12 || day < 1 || day > daysInMonth(year, month) || hour > 23 || minute > 59 || second > 59) return null;
  let offsetMinutes = 0;
  if (zone !== 'Z') {
    const sign = zone[0] === '+' ? 1 : -1;
    const offsetHour = Number(zone.slice(1, 3)); const offsetMinute = Number(zone.slice(4, 6));
    if (offsetHour > 23 || offsetMinute > 59) return null;
    offsetMinutes = sign * ((offsetHour * 60) + offsetMinute);
  }
  const utcMs = Date.UTC(year, month - 1, day, hour, minute, second) - (offsetMinutes * 60_000);
  if (!Number.isFinite(utcMs)) return null;
  return { utcMs, fraction };
}

function millisecondKey(value) {
  const parsed = parseRfc3339(value);
  if (!parsed) return null;
  const milliseconds = Number(parsed.fraction.slice(0, 3).padEnd(3, '0'));
  return new Date(parsed.utcMs + milliseconds).toISOString().slice(0, 23);
}

function normalizeWindow(from, to) {
  const start = from == null ? null : millisecondKey(from);
  const end = to == null ? null : millisecondKey(to);
  if ((from != null && !start) || (to != null && !end) || (start && end && start > end)) throw failure('invalid_request', 400);
  return { start, end };
}

function normalizeQuery(value) {
  const query = String(value ?? '').trim().replace(/[A-Z]/g, character => character.toLowerCase());
  if (Array.from(query).length > MAX_CONTENT_CODE_POINTS) throw failure('invalid_request', 400);
  return query;
}

function requireContext(context) {
  try {
    return normalizeOpaqueTagMap(context?.contextTags);
  } catch {
    throw failure('context_required', 403);
  }
}

function digest(value) {
  return crypto.createHash('sha256').update(canonicalJson(value)).digest('hex');
}

function mac(value, key) {
  return crypto.createHmac('sha256', key).update(canonicalJson(value)).digest('base64url');
}

function safeEqual(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') return false;
  const actual = Buffer.from(left, 'utf8'); const expected = Buffer.from(right, 'utf8');
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function isExactObject(value, keys) {
  return value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
}

function validState(operation, state) {
  if (operation === 'sessions_search') return isExactObject(state, ['e']) && CONVERSATION_ID.test(state.e);
  return isExactObject(state, ['t', 's', 'e']) && ORDER_KEY.test(state.t) && Number.isSafeInteger(state.s) && state.s >= 0 && EVENT_ID.test(state.e);
}

function encodeCursor(operation, binding, state, key) {
  const unsigned = { v: 1, o: operation, d: digest(binding), s: state };
  const body = Buffer.from(canonicalJson({ ...unsigned, m: mac(unsigned, key) }), 'utf8').toString('base64url');
  const cursor = `csv_${body}`;
  if (cursor.length > MAX_CURSOR_CHARS) throw new Error('conversation_session_view_cursor_oversize');
  return cursor;
}

function decodeCursor(value, operation, binding, key) {
  if (value == null) return null;
  if (typeof value !== 'string' || value.length > MAX_CURSOR_CHARS || !new RegExp(`^csv_[A-Za-z0-9_-]{16,${MAX_CURSOR_BODY_CHARS}}$`).test(value)) throw failure('invalid_request', 400);
  try {
    const body = value.slice(4);
    const bytes = Buffer.from(body, 'base64url');
    if (bytes.toString('base64url') !== body) throw failure('invalid_request', 400);
    const parsed = JSON.parse(bytes.toString('utf8'));
    if (!isExactObject(parsed, ['v', 'o', 'd', 's', 'm'])) throw failure('invalid_request', 400);
    const unsigned = { v: parsed.v, o: parsed.o, d: parsed.d, s: parsed.s };
    if (parsed.v !== 1 || parsed.o !== operation || !/^[a-f0-9]{64}$/.test(parsed.d) || parsed.d !== digest(binding) ||
      !validState(operation, parsed.s) || !safeEqual(parsed.m, mac(unsigned, key))) throw failure('invalid_request', 400);
    return parsed.s;
  } catch (caught) {
    if (caught?.status) throw caught;
    throw failure('invalid_request', 400);
  }
}

function field(alias, name, postgres) {
  return postgres ? `${alias}.event_json->>'${name}'` : `json_extract(${alias}.event_json,'$.${name}')`;
}

function visibleWhere(table, postgres, alias = 'e') {
  return `${alias}.expired=${postgres ? 'false' : '0'} AND ${alias}.state<>'conflict' AND ${alias}.state<>'tombstone' AND
    NOT EXISTS (SELECT 1 FROM ${table} h WHERE h.conversation_id=${alias}.conversation_id AND (
      (h.state='tombstone' AND ${field('h', 'tombstonesEventId', postgres)}=${alias}.event_id) OR
      (h.state IN ('edited','replacement') AND ${field('h', 'replacesEventId', postgres)}=${alias}.event_id)
    ))`;
}

function millisecondColumn(alias, postgres) {
  return postgres ? `left(${alias}.source_time_key,23)` : `substr(${alias}.source_time_key,1,23)`;
}

function parseTags(value) {
  try { return typeof value === 'string' ? JSON.parse(value) : value; } catch { return null; }
}

function metadataProjection(row, contextTags) {
  if (!row) return null;
  const tags = parseTags(row.context_tags);
  if (Number(row.event_count) < 1 || Number(row.source_count) !== 1 || Number(row.kind_count) !== 1 ||
    Number(row.context_count) !== 1 || !row.conversation_kind || !exactContextIntersection(tags, contextTags)) return null;
  return {
    id: row.conversation_id,
    runtime: 'conversation-v3',
    firstOccurredAt: row.first_occurred_at,
    lastOccurredAt: row.last_occurred_at,
    eventCount: Number(row.event_count),
    createdAt: row.first_occurred_at,
    title: '', scope: '', ownerSelf: true,
    conversationKind: row.conversation_kind,
    contextTags: tags
  };
}

function transcriptItem(row) {
  return {
    eventId: row.event_id,
    occurredAt: row.occurred_at,
    role: row.role,
    content: { redacted: true, contentType: 'text', parts: 1, text: truncateText(row.visible_text) }
  };
}

class ConversationSessionView {
  constructor({ cursorKey, scanLimit = MAX_SCAN_LIMIT } = {}) {
    this.cursorKey = Buffer.from(requireCursorKey(cursorKey));
    if (!Number.isSafeInteger(scanLimit) || scanLimit < 1 || scanLimit > MAX_SCAN_LIMIT) throw new TypeError('conversation_session_view_scan_limit_invalid');
    this.scanLimit = scanLimit;
    this.configured = true;
    this.kind = 'conversation-archive-v3';
  }

  _request({ operation, context, query, from, to, limit, id = null, cursor }) {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) throw failure('session_limit_invalid', 400);
    const contextTags = requireContext(context);
    if (id !== null && !CONVERSATION_ID.test(id)) throw failure('session_not_found', 404);
    const window = normalizeWindow(from, to);
    const normalizedQuery = normalizeQuery(query);
    const binding = { operation, context: digest(contextTags), id, query: normalizedQuery, from: window.start, to: window.end, limit };
    return { contextTags, window, query: normalizedQuery, limit, binding, state: decodeCursor(cursor, operation, binding, this.cursorKey) };
  }

  async get({ id, context }) {
    if (!CONVERSATION_ID.test(id)) throw failure('session_not_found', 404);
    const contextTags = requireContext(context);
    const metadata = metadataProjection(await this._metadata(id), contextTags);
    if (!metadata) throw failure('session_not_found', 404);
    return metadata;
  }

  async transcript({ id, view, cursor = null, limit = 100, query = '', from = null, to = null, context }) {
    if (view !== 'redacted') throw failure('session_original_unavailable', 410);
    const request = this._request({ operation: 'session_transcript', context, query, from, to, limit, id, cursor });
    const metadata = metadataProjection(await this._metadata(id), request.contextTags);
    if (!metadata) throw failure('session_not_found', 404);
    const rows = await this._transcriptPage(id, request);
    const page = rows.slice(0, request.limit);
    return {
      id, view: 'redacted', items: page.map(transcriptItem),
      nextCursor: rows.length > page.length ? encodeCursor('session_transcript', request.binding, {
        t: page.at(-1).source_time_key, s: Number(page.at(-1).source_sequence), e: page.at(-1).event_id
      }, this.cursorKey) : null
    };
  }

  async search({ query = '', cursor = null, limit = 20, from = null, to = null, context }) {
    const request = this._request({ operation: 'sessions_search', context, query, from, to, limit, cursor });
    const candidates = await this._candidateConversations(request);
    const items = [];
    let scanned = null;
    for (const candidate of candidates) {
      scanned = candidate;
      const metadata = metadataProjection(await this._metadata(candidate.conversation_id), request.contextTags);
      if (metadata) items.push(metadata);
      if (items.length === request.limit) break;
    }
    const more = scanned && (scanned !== candidates.at(-1) || candidates.length === this.scanLimit);
    return { items, total: items.length, nextCursor: more ? encodeCursor('sessions_search', request.binding, { e: scanned.conversation_id }, this.cursorKey) : null };
  }
}

function sqliteMetadataSql() {
  const visible = visibleWhere('conversation_archive_events_v1', false);
  const first = visibleWhere('conversation_archive_events_v1', false, 'f');
  const last = visibleWhere('conversation_archive_events_v1', false, 'l');
  return `SELECT e.conversation_id, COUNT(*) event_count, COUNT(DISTINCT e.source_instance_id) source_count,
      MIN(json_extract(e.event_json,'$.conversationKind')) conversation_kind, COUNT(DISTINCT json_extract(e.event_json,'$.conversationKind')) kind_count,
      MIN(json_extract(e.event_json,'$.authorizationContextTags')) context_tags, COUNT(DISTINCT json_extract(e.event_json,'$.authorizationContextTags')) context_count,
      (SELECT f.source_occurred_at FROM conversation_archive_events_v1 f WHERE ${first} AND ${field('f', 'role', false)} IN ('user','assistant') AND f.conversation_id=? ORDER BY f.source_time_key,f.source_sequence,f.event_id LIMIT 1) first_occurred_at,
      (SELECT l.source_occurred_at FROM conversation_archive_events_v1 l WHERE ${last} AND ${field('l', 'role', false)} IN ('user','assistant') AND l.conversation_id=? ORDER BY l.source_time_key DESC,l.source_sequence DESC,l.event_id DESC LIMIT 1) last_occurred_at
    FROM conversation_archive_events_v1 e WHERE ${visible} AND ${field('e', 'role', false)} IN ('user','assistant') AND e.conversation_id=? GROUP BY e.conversation_id`;
}

function postgresMetadataSql() {
  const visible = visibleWhere('agent_memory_fabric.conversation_archive_events_v1', true);
  const first = visibleWhere('agent_memory_fabric.conversation_archive_events_v1', true, 'f');
  const last = visibleWhere('agent_memory_fabric.conversation_archive_events_v1', true, 'l');
  return `SELECT e.conversation_id, COUNT(*) event_count, COUNT(DISTINCT e.source_instance_id) source_count,
      MIN(e.event_json->>'conversationKind') conversation_kind, COUNT(DISTINCT e.event_json->>'conversationKind') kind_count,
      MIN(e.event_json->>'authorizationContextTags') context_tags, COUNT(DISTINCT e.event_json->>'authorizationContextTags') context_count,
      (SELECT f.source_occurred_at FROM agent_memory_fabric.conversation_archive_events_v1 f WHERE ${first} AND ${field('f', 'role', true)} IN ('user','assistant') AND f.conversation_id=$1 ORDER BY f.source_time_key,f.source_sequence,f.event_id LIMIT 1) first_occurred_at,
      (SELECT l.source_occurred_at FROM agent_memory_fabric.conversation_archive_events_v1 l WHERE ${last} AND ${field('l', 'role', true)} IN ('user','assistant') AND l.conversation_id=$2 ORDER BY l.source_time_key DESC,l.source_sequence DESC,l.event_id DESC LIMIT 1) last_occurred_at
    FROM agent_memory_fabric.conversation_archive_events_v1 e WHERE ${visible} AND ${field('e', 'role', true)} IN ('user','assistant') AND e.conversation_id=$3 GROUP BY e.conversation_id`;
}

export class SqliteConversationSessionView extends ConversationSessionView {
  constructor({ db, ...options } = {}) {
    super(options);
    if (!db?.prepare) throw new TypeError('conversation_session_view_sqlite_invalid');
    this.db = db;
  }

  async _metadata(id) {
    return this.db.prepare(sqliteMetadataSql()).get(id, id, id);
  }

  async _transcriptPage(id, request) {
    const clauses = [visibleWhere('conversation_archive_events_v1', false), `${field('e', 'role', false)} IN ('user','assistant')`, 'e.conversation_id=?'];
    const values = [id];
    if (request.window.start) { clauses.push(`${millisecondColumn('e', false)}>=?`); values.push(request.window.start); }
    if (request.window.end) { clauses.push(`${millisecondColumn('e', false)}<=?`); values.push(request.window.end); }
    if (request.query) { clauses.push(`instr(lower(substr(${field('e', 'visibleText', false)},1,?)),?)>0`); values.push(MAX_CONTENT_CODE_POINTS, request.query); }
    if (request.state) { clauses.push('(e.source_time_key>? OR (e.source_time_key=? AND (e.source_sequence>? OR (e.source_sequence=? AND e.event_id>?))))'); values.push(request.state.t, request.state.t, request.state.s, request.state.s, request.state.e); }
    return this.db.prepare(`SELECT e.event_id,e.source_occurred_at,e.source_time_key,e.source_sequence,${field('e', 'occurredAt', false)} occurred_at,
      ${field('e', 'role', false)} role,${field('e', 'visibleText', false)} visible_text FROM conversation_archive_events_v1 e
      WHERE ${clauses.join(' AND ')} ORDER BY e.source_time_key,e.source_sequence,e.event_id LIMIT ?`).all(...values, request.limit + 1);
  }

  async _candidateConversations(request) {
    const clauses = [visibleWhere('conversation_archive_events_v1', false), `${field('e', 'role', false)} IN ('user','assistant')`];
    const values = [];
    if (request.state) { clauses.push('e.conversation_id>?'); values.push(request.state.e); }
    if (request.query) {
      const matched = [visibleWhere('conversation_archive_events_v1', false, 'm'), `${field('m', 'role', false)} IN ('user','assistant')`, 'm.conversation_id=e.conversation_id'];
      if (request.window.start) { matched.push(`${millisecondColumn('m', false)}>=?`); values.push(request.window.start); }
      if (request.window.end) { matched.push(`${millisecondColumn('m', false)}<=?`); values.push(request.window.end); }
      matched.push(`instr(lower(substr(${field('m', 'visibleText', false)},1,?)),?)>0`); values.push(MAX_CONTENT_CODE_POINTS, request.query);
      clauses.push(`EXISTS (SELECT 1 FROM conversation_archive_events_v1 m WHERE ${matched.join(' AND ')})`);
    } else {
      if (request.window.start) {
        clauses.push(`EXISTS (SELECT 1 FROM conversation_archive_events_v1 after_window WHERE ${visibleWhere('conversation_archive_events_v1', false, 'after_window')} AND ${field('after_window', 'role', false)} IN ('user','assistant') AND after_window.conversation_id=e.conversation_id AND ${millisecondColumn('after_window', false)}>=?)`);
        values.push(request.window.start);
      }
      if (request.window.end) {
        clauses.push(`EXISTS (SELECT 1 FROM conversation_archive_events_v1 before_window WHERE ${visibleWhere('conversation_archive_events_v1', false, 'before_window')} AND ${field('before_window', 'role', false)} IN ('user','assistant') AND before_window.conversation_id=e.conversation_id AND ${millisecondColumn('before_window', false)}<=?)`);
        values.push(request.window.end);
      }
    }
    values.push(this.scanLimit);
    return this.db.prepare(`SELECT DISTINCT e.conversation_id FROM conversation_archive_events_v1 e WHERE ${clauses.join(' AND ')} ORDER BY e.conversation_id LIMIT ?`).all(...values);
  }
}

export class PostgresConversationSessionView extends ConversationSessionView {
  constructor({ pool, ...options } = {}) {
    super(options);
    if (!pool?.query) throw new TypeError('conversation_session_view_postgres_invalid');
    this.pool = pool;
  }

  async _metadata(id) {
    return (await this.pool.query(postgresMetadataSql(), [id, id, id])).rows[0];
  }

  async _transcriptPage(id, request) {
    const clauses = [visibleWhere('agent_memory_fabric.conversation_archive_events_v1', true), `${field('e', 'role', true)} IN ('user','assistant')`, 'e.conversation_id=$1'];
    const values = [id];
    const add = (clause, value) => { values.push(value); clauses.push(clause.replace('?', `$${values.length}`)); };
    if (request.window.start) add(`${millisecondColumn('e', true)}>=?`, request.window.start);
    if (request.window.end) add(`${millisecondColumn('e', true)}<=?`, request.window.end);
    if (request.query) add(`position(? in translate(left(${field('e', 'visibleText', true)},${MAX_CONTENT_CODE_POINTS}),'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz'))>0`, request.query);
    if (request.state) { values.push(request.state.t, request.state.s, request.state.e); clauses.push(`(e.source_time_key,e.source_sequence,e.event_id)>($${values.length - 2},$${values.length - 1},$${values.length})`); }
    values.push(request.limit + 1);
    return (await this.pool.query(`SELECT e.event_id,e.source_occurred_at,e.source_time_key,e.source_sequence,${field('e', 'occurredAt', true)} occurred_at,
      ${field('e', 'role', true)} role,${field('e', 'visibleText', true)} visible_text FROM agent_memory_fabric.conversation_archive_events_v1 e
      WHERE ${clauses.join(' AND ')} ORDER BY e.source_time_key,e.source_sequence,e.event_id LIMIT $${values.length}`, values)).rows;
  }

  async _candidateConversations(request) {
    const clauses = [visibleWhere('agent_memory_fabric.conversation_archive_events_v1', true), `${field('e', 'role', true)} IN ('user','assistant')`];
    const values = [];
    const add = (clause, value) => { values.push(value); clauses.push(clause.replace('?', `$${values.length}`)); };
    if (request.state) add('e.conversation_id>?', request.state.e);
    if (request.query) {
      const matched = [visibleWhere('agent_memory_fabric.conversation_archive_events_v1', true, 'm'), `${field('m', 'role', true)} IN ('user','assistant')`, 'm.conversation_id=e.conversation_id'];
      const addMatched = (clause, value) => { values.push(value); matched.push(clause.replace('?', `$${values.length}`)); };
      if (request.window.start) addMatched(`${millisecondColumn('m', true)}>=?`, request.window.start);
      if (request.window.end) addMatched(`${millisecondColumn('m', true)}<=?`, request.window.end);
      addMatched(`position(? in translate(left(${field('m', 'visibleText', true)},${MAX_CONTENT_CODE_POINTS}),'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz'))>0`, request.query);
      clauses.push(`EXISTS (SELECT 1 FROM agent_memory_fabric.conversation_archive_events_v1 m WHERE ${matched.join(' AND ')})`);
    } else {
      if (request.window.start) {
        const after = [visibleWhere('agent_memory_fabric.conversation_archive_events_v1', true, 'after_window'), `${field('after_window', 'role', true)} IN ('user','assistant')`, 'after_window.conversation_id=e.conversation_id'];
        values.push(request.window.start);
        after.push(`${millisecondColumn('after_window', true)}>=$${values.length}`);
        clauses.push(`EXISTS (SELECT 1 FROM agent_memory_fabric.conversation_archive_events_v1 after_window WHERE ${after.join(' AND ')})`);
      }
      if (request.window.end) {
        const before = [visibleWhere('agent_memory_fabric.conversation_archive_events_v1', true, 'before_window'), `${field('before_window', 'role', true)} IN ('user','assistant')`, 'before_window.conversation_id=e.conversation_id'];
        values.push(request.window.end);
        before.push(`${millisecondColumn('before_window', true)}<=$${values.length}`);
        clauses.push(`EXISTS (SELECT 1 FROM agent_memory_fabric.conversation_archive_events_v1 before_window WHERE ${before.join(' AND ')})`);
      }
    }
    values.push(this.scanLimit);
    return (await this.pool.query(`SELECT DISTINCT e.conversation_id FROM agent_memory_fabric.conversation_archive_events_v1 e
      WHERE ${clauses.join(' AND ')} ORDER BY e.conversation_id LIMIT $${values.length}`, values)).rows;
  }
}
