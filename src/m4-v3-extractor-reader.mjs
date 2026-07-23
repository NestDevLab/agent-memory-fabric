import crypto from 'node:crypto';

import { normalizeOpaqueTagMap } from './access-contract.mjs';
import { isConversationEventUtcTimestamp } from './conversation-event-v3.mjs';
import { canonicalJson } from './ingest/transcripts/canonical.mjs';
import { createM4ConversationArchiveCoverageBinding, M4_CONVERSATION_EXTRACTOR_ALIASES_MAX } from './migration/m4-conversation-extractor-aliases.mjs';

const CONVERSATION_ID = /^ccon_[a-z0-9][a-z0-9_-]{7,127}$/;
const EVENT_ID = /^cevt_[a-z0-9][a-z0-9_-]{7,127}$/;
const EXTRACTION_IDENTITY = /^(?:ses_[a-f0-9]{64}|ccon_[a-z0-9][a-z0-9_-]{7,127})$/;
const ORDER_KEY = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{9}$/;
const KINDS = new Set(['dm', 'group', 'channel', 'thread', 'session']);
const MAX_CURSOR_CHARS = 1024;
const MAX_TEXT_CODE_POINTS = 4096;
const MAX_VISIBLE_REVISION_EVENTS = 10_000;
const VISIBLE_REVISION_DIGEST = /^sha256:[a-f0-9]{64}$/;
const REVISION_FIELD_SEPARATOR = '\u001f';
const REVISION_RECORD_SEPARATOR = '\u001e';

function failure(code) { const error = new Error(code); error.code = code; return error; }
function fail(code) { throw failure(code); }
function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function exact(value, keys) { return plain(value) && Object.keys(value).sort().join('\0') === [...keys].sort().join('\0'); }
function requireKey(value) {
  if (!Buffer.isBuffer(value) || value.length !== 32) fail('m4_v3_extractor_cursor_key_invalid');
  return Buffer.from(value);
}
function digest(value) { return crypto.createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex'); }
function mac(value, key) { return crypto.createHmac('sha256', key).update(canonicalJson(value), 'utf8').digest('base64url'); }
function safeEqual(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') return false;
  const actual = Buffer.from(left, 'utf8'); const expected = Buffer.from(right, 'utf8');
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}
function validSequence(value) { const number = Number(value); return Number.isSafeInteger(number) && number >= 0 ? number : null; }
function validSearchState(value) {
  return exact(value, ['t', 's', 'e', 'c']) && ORDER_KEY.test(value.t) && validSequence(value.s) !== null
    && EVENT_ID.test(value.e) && CONVERSATION_ID.test(value.c);
}
function validTranscriptState(value) {
  return exact(value, ['t', 's', 'e']) && ORDER_KEY.test(value.t) && validSequence(value.s) !== null && EVENT_ID.test(value.e);
}
function encodeCursor(operation, binding, state, key) {
  const unsigned = { v: 1, o: operation, d: digest(binding), s: state };
  const cursor = `m4x_${Buffer.from(canonicalJson({ ...unsigned, m: mac(unsigned, key) }), 'utf8').toString('base64url')}`;
  if (cursor.length > MAX_CURSOR_CHARS) fail('m4_v3_extractor_cursor_oversize');
  return cursor;
}
function decodeCursor(value, operation, binding, key) {
  if (value == null) return null;
  if (typeof value !== 'string' || value.length > MAX_CURSOR_CHARS || !/^m4x_[A-Za-z0-9_-]{16,1020}$/.test(value)) fail('m4_v3_extractor_cursor_invalid');
  try {
    const body = value.slice(4); const bytes = Buffer.from(body, 'base64url');
    if (bytes.toString('base64url') !== body) fail('m4_v3_extractor_cursor_invalid');
    const parsed = JSON.parse(bytes.toString('utf8'));
    if (!exact(parsed, ['v', 'o', 'd', 's', 'm']) || parsed.v !== 1 || parsed.o !== operation
      || parsed.d !== digest(binding) || !/^[a-f0-9]{64}$/.test(parsed.d)
      || !(operation === 'search' ? validSearchState(parsed.s) : validTranscriptState(parsed.s))) fail('m4_v3_extractor_cursor_invalid');
    const unsigned = { v: parsed.v, o: parsed.o, d: parsed.d, s: parsed.s };
    if (!safeEqual(parsed.m, mac(unsigned, key))) fail('m4_v3_extractor_cursor_invalid');
    return parsed.s;
  } catch (error) {
    if (error?.code) throw error;
    fail('m4_v3_extractor_cursor_invalid');
  }
}
function limit(value, fallback) {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || result < 1 || result > 100) fail('m4_v3_extractor_request_invalid');
  return result;
}
function truncate(value) { return Array.from(String(value)).slice(0, MAX_TEXT_CODE_POINTS).join(''); }
function field(alias, name, postgres) { return postgres ? `${alias}.event_json->>'${name}'` : `json_extract(${alias}.event_json,'$.${name}')`; }
function visible(table, postgres, alias = 'e') {
  return `${alias}.expired=${postgres ? 'false' : '0'} AND ${alias}.state<>'conflict' AND ${alias}.state<>'tombstone' AND
    NOT EXISTS (SELECT 1 FROM ${table} h WHERE h.conversation_id=${alias}.conversation_id AND (
      (h.state='tombstone' AND ${field('h', 'tombstonesEventId', postgres)}=${alias}.event_id) OR
      (h.state IN ('edited','replacement') AND ${field('h', 'replacesEventId', postgres)}=${alias}.event_id)
    ))`;
}
function contextTags(value) {
  try { return normalizeOpaqueTagMap(typeof value === 'string' ? JSON.parse(value) : value); }
  catch { fail('m4_v3_extractor_archive_invalid'); }
}
function visibleRevisionEvents(value, count) {
  if (count > MAX_VISIBLE_REVISION_EVENTS || typeof value !== 'string' || value.length < 1
    || value.length > MAX_VISIBLE_REVISION_EVENTS * 192) fail('m4_v3_extractor_archive_invalid');
  const events = value.split(REVISION_RECORD_SEPARATOR);
  if (events.length !== count) fail('m4_v3_extractor_archive_invalid');
  let previous = null;
  return events.map(item => {
    const [timeKey, sequenceText, eventId, ...extra] = item.split(REVISION_FIELD_SEPARATOR);
    const sequence = validSequence(sequenceText);
    if (extra.length || !ORDER_KEY.test(timeKey) || !/^(?:0|[1-9]\d*)$/.test(sequenceText) || sequence === null || !EVENT_ID.test(eventId)) {
      fail('m4_v3_extractor_archive_invalid');
    }
    const current = [timeKey, sequence, eventId];
    if (previous && (previous[0] > current[0] || (previous[0] === current[0] && (previous[1] > current[1]
      || (previous[1] === current[1] && previous[2] >= current[2]))))) fail('m4_v3_extractor_archive_invalid');
    previous = current;
    return { timeKey, sequence, eventId };
  });
}
function metadata(row, resolveIdentity) {
  const count = Number(row?.event_count); const first = row?.first_occurred_at; const last = row?.last_occurred_at;
  const firstSequence = validSequence(row?.first_sequence); const lastSequence = validSequence(row?.last_sequence);
  if (!row || !CONVERSATION_ID.test(row.conversation_id) || !Number.isSafeInteger(count) || count < 1
    || Number(row.source_count) !== 1 || Number(row.kind_count) !== 1 || Number(row.context_count) !== 1
    || !KINDS.has(row.conversation_kind) || !isConversationEventUtcTimestamp(first) || !isConversationEventUtcTimestamp(last)
    || !ORDER_KEY.test(row.first_time_key) || firstSequence === null || !EVENT_ID.test(row.first_event_id)
    || !ORDER_KEY.test(row.last_time_key) || lastSequence === null || !EVENT_ID.test(row.last_event_id)) {
    fail('m4_v3_extractor_not_found');
  }
  const visibleEvents = visibleRevisionEvents(row.visible_event_identities, count);
  const firstEvent = visibleEvents[0]; const lastEvent = visibleEvents.at(-1);
  if (firstEvent.timeKey !== row.first_time_key || firstEvent.sequence !== firstSequence || firstEvent.eventId !== row.first_event_id
    || lastEvent.timeKey !== row.last_time_key || lastEvent.sequence !== lastSequence || lastEvent.eventId !== row.last_event_id) {
    fail('m4_v3_extractor_archive_invalid');
  }
  let extractionIdentity;
  try { extractionIdentity = resolveIdentity({ conversationId: row.conversation_id, firstOccurredAt: first, lastOccurredAt: last }); }
  catch { fail('m4_v3_extractor_identity_invalid'); }
  if (typeof extractionIdentity !== 'string' || !EXTRACTION_IDENTITY.test(extractionIdentity)) fail('m4_v3_extractor_identity_invalid');
  const visibleRevisionDigest = `sha256:${digest({ schema: 'amf.conversation-visible-revision/v1', conversationId: row.conversation_id,
    visibleEventCount: count, visibleEvents })}`;
  if (!VISIBLE_REVISION_DIGEST.test(visibleRevisionDigest)) fail('m4_v3_extractor_archive_invalid');
  return { id: row.conversation_id, firstOccurredAt: first, lastOccurredAt: last, eventCount: count,
    conversationKind: row.conversation_kind, contextTags: contextTags(row.context_tags), extractionIdentity, visibleRevisionDigest };
}
function searchKey(row) {
  const sequence = validSequence(row?.last_sequence);
  if (!CONVERSATION_ID.test(row?.conversation_id) || !ORDER_KEY.test(row?.last_time_key)
    || sequence === null || !EVENT_ID.test(row?.last_event_id)) fail('m4_v3_extractor_archive_invalid');
  return { t: row.last_time_key, s: sequence, e: row.last_event_id, c: row.conversation_id };
}
function transcriptItem(row) {
  if (!EVENT_ID.test(row?.event_id) || !ORDER_KEY.test(row?.source_time_key) || validSequence(row?.source_sequence) === null
    || !isConversationEventUtcTimestamp(row?.occurred_at) || !['user', 'assistant'].includes(row?.role)
    || typeof row?.visible_text !== 'string') fail('m4_v3_extractor_archive_invalid');
  return { eventId: row.event_id, occurredAt: row.occurred_at, role: row.role,
    content: { redacted: true, contentType: 'text', parts: 1, text: truncate(row.visible_text) } };
}

class M4V3ExtractorReader {
  constructor({ cursorKey, identityResolver } = {}) {
    this.cursorKey = requireKey(cursorKey);
    const resolve = typeof identityResolver === 'function' ? identityResolver : identityResolver?.resolve?.bind(identityResolver);
    if (typeof resolve !== 'function') fail('m4_v3_extractor_identity_invalid');
    this.resolveIdentity = resolve; this.coverageBinding = identityResolver?.coverageBinding ?? null;
    this.configured = true; this.kind = 'conversation-archive-v3-extractor';
  }

  async verifyCoverage() {
    const expected = this.coverageBinding;
    if (!plain(expected) || !isConversationEventUtcTimestamp(expected.coveredThrough)
      || !ORDER_KEY.test(expected.coveredThroughKey) || !Number.isSafeInteger(expected.conversationCount)
      || expected.conversationCount < 0 || expected.conversationCount > M4_CONVERSATION_EXTRACTOR_ALIASES_MAX
      || !/^sha256:[a-f0-9]{64}$/.test(expected.conversationDigest)) fail('m4_v3_extractor_coverage_invalid');
    const rows = await this._coverage(expected.coveredThroughKey, M4_CONVERSATION_EXTRACTOR_ALIASES_MAX + 1);
    if (!Array.isArray(rows) || rows.length > M4_CONVERSATION_EXTRACTOR_ALIASES_MAX) fail('m4_v3_extractor_coverage_invalid');
    const ids = rows.map((row, index) => {
      if (!CONVERSATION_ID.test(row?.conversation_id) || !ORDER_KEY.test(row?.first_time_key)
        || row.first_time_key > expected.coveredThroughKey
        || (index > 0 && rows[index - 1]?.conversation_id >= row.conversation_id)) fail('m4_v3_extractor_coverage_invalid');
      return row.conversation_id;
    });
    const actual = createM4ConversationArchiveCoverageBinding(ids);
    if (actual.conversationCount !== expected.conversationCount || actual.conversationDigest !== expected.conversationDigest) {
      fail('m4_v3_extractor_coverage_invalid');
    }
  }

  async get({ id } = {}) {
    if (!CONVERSATION_ID.test(id)) fail('m4_v3_extractor_not_found');
    return metadata(await this._metadata(id), this.resolveIdentity);
  }

  async search({ cursor = null, limit: requestedLimit = 20 } = {}) {
    const pageLimit = limit(requestedLimit, 20); const state = decodeCursor(cursor, 'search', { order: 'newest-v1' }, this.cursorKey);
    const rows = await this._search(state, pageLimit + 1); if (!Array.isArray(rows)) fail('m4_v3_extractor_archive_invalid');
    const page = rows.slice(0, pageLimit); const items = [];
    for (const row of page) { searchKey(row); items.push(await this.get({ id: row.conversation_id })); }
    return { items, total: items.length, nextCursor: rows.length > page.length && page.length
      ? encodeCursor('search', { order: 'newest-v1' }, searchKey(page.at(-1)), this.cursorKey) : null };
  }

  async transcript({ id, view, cursor = null, limit: requestedLimit = 100, newest = true } = {}) {
    if (!CONVERSATION_ID.test(id) || view !== 'redacted' || newest !== true) fail('m4_v3_extractor_request_invalid');
    const pageLimit = limit(requestedLimit, 100); const state = decodeCursor(cursor, 'transcript', { id, order: 'newest-v1' }, this.cursorKey);
    await this.get({ id });
    const rows = await this._transcript(id, state, pageLimit + 1); if (!Array.isArray(rows)) fail('m4_v3_extractor_archive_invalid');
    const page = rows.slice(0, pageLimit); const items = page.map(transcriptItem);
    const last = page.at(-1); const nextCursor = rows.length > page.length && last
      ? encodeCursor('transcript', { id, order: 'newest-v1' }, { t: last.source_time_key,
        s: validSequence(last.source_sequence), e: last.event_id }, this.cursorKey) : null;
    return { id, view: 'redacted', items, nextCursor };
  }
}

const SQLITE_TABLE = 'conversation_archive_events_v1';
const POSTGRES_TABLE = 'agent_memory_fabric.conversation_archive_events_v1';

function sqliteMetadataSql() {
  const current = visible(SQLITE_TABLE, false);
  return `WITH visible_events AS (SELECT e.* FROM ${SQLITE_TABLE} e WHERE ${current} AND ${field('e', 'role', false)} IN ('user','assistant') AND e.conversation_id=?)
    SELECT e.conversation_id,COUNT(*) event_count,COUNT(DISTINCT e.source_instance_id) source_count,
      MIN(${field('e', 'conversationKind', false)}) conversation_kind,COUNT(DISTINCT ${field('e', 'conversationKind', false)}) kind_count,
      MIN(${field('e', 'authorizationContextTags', false)}) context_tags,COUNT(DISTINCT ${field('e', 'authorizationContextTags', false)}) context_count,
      (SELECT f.source_occurred_at FROM visible_events f WHERE f.conversation_id=e.conversation_id ORDER BY f.source_time_key,f.source_sequence,f.event_id LIMIT 1) first_occurred_at,
      (SELECT f.source_time_key FROM visible_events f WHERE f.conversation_id=e.conversation_id ORDER BY f.source_time_key,f.source_sequence,f.event_id LIMIT 1) first_time_key,
      (SELECT f.source_sequence FROM visible_events f WHERE f.conversation_id=e.conversation_id ORDER BY f.source_time_key,f.source_sequence,f.event_id LIMIT 1) first_sequence,
      (SELECT f.event_id FROM visible_events f WHERE f.conversation_id=e.conversation_id ORDER BY f.source_time_key,f.source_sequence,f.event_id LIMIT 1) first_event_id,
      (SELECT l.source_occurred_at FROM visible_events l WHERE l.conversation_id=e.conversation_id ORDER BY l.source_time_key DESC,l.source_sequence DESC,l.event_id DESC LIMIT 1) last_occurred_at,
      (SELECT l.source_time_key FROM visible_events l WHERE l.conversation_id=e.conversation_id ORDER BY l.source_time_key DESC,l.source_sequence DESC,l.event_id DESC LIMIT 1) last_time_key,
      (SELECT l.source_sequence FROM visible_events l WHERE l.conversation_id=e.conversation_id ORDER BY l.source_time_key DESC,l.source_sequence DESC,l.event_id DESC LIMIT 1) last_sequence,
      (SELECT l.event_id FROM visible_events l WHERE l.conversation_id=e.conversation_id ORDER BY l.source_time_key DESC,l.source_sequence DESC,l.event_id DESC LIMIT 1) last_event_id,
      (SELECT group_concat(identity, char(30)) FROM (SELECT f.source_time_key || char(31) || CAST(f.source_sequence AS TEXT) || char(31) || f.event_id identity FROM visible_events f WHERE f.conversation_id=e.conversation_id ORDER BY f.source_time_key,f.source_sequence,f.event_id LIMIT ${MAX_VISIBLE_REVISION_EVENTS + 1})) visible_event_identities
    FROM visible_events e GROUP BY e.conversation_id`;
}
function postgresMetadataSql() {
  const current = visible(POSTGRES_TABLE, true);
  return `WITH visible_events AS (SELECT e.* FROM ${POSTGRES_TABLE} e WHERE ${current} AND ${field('e', 'role', true)} IN ('user','assistant') AND e.conversation_id=$1)
    SELECT e.conversation_id,COUNT(*) event_count,COUNT(DISTINCT e.source_instance_id) source_count,
      MIN(${field('e', 'conversationKind', true)}) conversation_kind,COUNT(DISTINCT ${field('e', 'conversationKind', true)}) kind_count,
      MIN(${field('e', 'authorizationContextTags', true)}) context_tags,COUNT(DISTINCT ${field('e', 'authorizationContextTags', true)}) context_count,
      (SELECT f.source_occurred_at FROM visible_events f WHERE f.conversation_id=e.conversation_id ORDER BY f.source_time_key,f.source_sequence,f.event_id LIMIT 1) first_occurred_at,
      (SELECT f.source_time_key FROM visible_events f WHERE f.conversation_id=e.conversation_id ORDER BY f.source_time_key,f.source_sequence,f.event_id LIMIT 1) first_time_key,
      (SELECT f.source_sequence FROM visible_events f WHERE f.conversation_id=e.conversation_id ORDER BY f.source_time_key,f.source_sequence,f.event_id LIMIT 1) first_sequence,
      (SELECT f.event_id FROM visible_events f WHERE f.conversation_id=e.conversation_id ORDER BY f.source_time_key,f.source_sequence,f.event_id LIMIT 1) first_event_id,
      (SELECT l.source_occurred_at FROM visible_events l WHERE l.conversation_id=e.conversation_id ORDER BY l.source_time_key DESC,l.source_sequence DESC,l.event_id DESC LIMIT 1) last_occurred_at,
      (SELECT l.source_time_key FROM visible_events l WHERE l.conversation_id=e.conversation_id ORDER BY l.source_time_key DESC,l.source_sequence DESC,l.event_id DESC LIMIT 1) last_time_key,
      (SELECT l.source_sequence FROM visible_events l WHERE l.conversation_id=e.conversation_id ORDER BY l.source_time_key DESC,l.source_sequence DESC,l.event_id DESC LIMIT 1) last_sequence,
      (SELECT l.event_id FROM visible_events l WHERE l.conversation_id=e.conversation_id ORDER BY l.source_time_key DESC,l.source_sequence DESC,l.event_id DESC LIMIT 1) last_event_id,
      (SELECT string_agg(identity, chr(30) ORDER BY source_time_key,source_sequence,event_id) FROM (SELECT f.source_time_key,f.source_sequence,f.event_id,f.source_time_key || chr(31) || f.source_sequence::text || chr(31) || f.event_id identity FROM visible_events f WHERE f.conversation_id=e.conversation_id ORDER BY f.source_time_key,f.source_sequence,f.event_id LIMIT ${MAX_VISIBLE_REVISION_EVENTS + 1}) revision_events) visible_event_identities
    FROM visible_events e GROUP BY e.conversation_id`;
}

export class SqliteM4V3ExtractorReader extends M4V3ExtractorReader {
  constructor({ db, ...options } = {}) { super(options); if (!db?.prepare) fail('m4_v3_extractor_sqlite_invalid'); this.db = db; }
  async _metadata(id) { return this.db.prepare(sqliteMetadataSql()).get(id); }
  async _coverage(cutoff, rowLimit) {
    return this.db.prepare(`SELECT e.conversation_id,MIN(e.source_time_key) first_time_key FROM ${SQLITE_TABLE} e
      WHERE ${visible(SQLITE_TABLE, false)} AND ${field('e', 'role', false)} IN ('user','assistant')
      GROUP BY e.conversation_id HAVING MIN(e.source_time_key)<=? ORDER BY e.conversation_id LIMIT ?`).all(cutoff, rowLimit);
  }
  async _search(state, pageLimit) {
    const values = []; const after = state ? 'AND (source_time_key,source_sequence,event_id,conversation_id)<(?,?,?,?)' : '';
    if (state) values.push(state.t, state.s, state.e, state.c); values.push(pageLimit);
    return this.db.prepare(`WITH visible_events AS (SELECT e.*,ROW_NUMBER() OVER (PARTITION BY e.conversation_id ORDER BY e.source_time_key DESC,e.source_sequence DESC,e.event_id DESC) ordinal FROM ${SQLITE_TABLE} e WHERE ${visible(SQLITE_TABLE, false)} AND ${field('e', 'role', false)} IN ('user','assistant'))
      SELECT conversation_id,source_time_key last_time_key,source_sequence last_sequence,event_id last_event_id FROM visible_events WHERE ordinal=1 ${after} ORDER BY source_time_key DESC,source_sequence DESC,event_id DESC,conversation_id DESC LIMIT ?`).all(...values);
  }
  async _transcript(id, state, pageLimit) {
    const clauses = [visible(SQLITE_TABLE, false), 'e.conversation_id=?', `${field('e', 'role', false)} IN ('user','assistant')`]; const values = [id];
    if (state) { clauses.push('(e.source_time_key,e.source_sequence,e.event_id)<(?,?,?)'); values.push(state.t, state.s, state.e); }
    values.push(pageLimit);
    return this.db.prepare(`SELECT e.event_id,${field('e', 'occurredAt', false)} occurred_at,e.source_time_key,e.source_sequence,
      ${field('e', 'role', false)} role,${field('e', 'visibleText', false)} visible_text FROM ${SQLITE_TABLE} e WHERE ${clauses.join(' AND ')}
      ORDER BY e.source_time_key DESC,e.source_sequence DESC,e.event_id DESC LIMIT ?`).all(...values);
  }
}

export class PostgresM4V3ExtractorReader extends M4V3ExtractorReader {
  constructor({ pool, ...options } = {}) { super(options); if (!pool?.query) fail('m4_v3_extractor_postgres_invalid'); this.pool = pool; }
  async _metadata(id) { return (await this.pool.query(postgresMetadataSql(), [id])).rows[0]; }
  async _coverage(cutoff, rowLimit) {
    return (await this.pool.query(`SELECT e.conversation_id,MIN(e.source_time_key) first_time_key FROM ${POSTGRES_TABLE} e
      WHERE ${visible(POSTGRES_TABLE, true)} AND ${field('e', 'role', true)} IN ('user','assistant')
      GROUP BY e.conversation_id HAVING MIN(e.source_time_key)<=$1 ORDER BY e.conversation_id LIMIT $2`, [cutoff, rowLimit])).rows;
  }
  async _search(state, pageLimit) {
    const values = []; let after = '';
    if (state) { values.push(state.t, state.s, state.e, state.c); after = 'AND (source_time_key,source_sequence,event_id,conversation_id)<($1,$2,$3,$4)'; }
    values.push(pageLimit);
    return (await this.pool.query(`WITH visible_events AS (SELECT e.*,ROW_NUMBER() OVER (PARTITION BY e.conversation_id ORDER BY e.source_time_key DESC,e.source_sequence DESC,e.event_id DESC) ordinal FROM ${POSTGRES_TABLE} e WHERE ${visible(POSTGRES_TABLE, true)} AND ${field('e', 'role', true)} IN ('user','assistant'))
      SELECT conversation_id,source_time_key last_time_key,source_sequence last_sequence,event_id last_event_id FROM visible_events WHERE ordinal=1 ${after} ORDER BY source_time_key DESC,source_sequence DESC,event_id DESC,conversation_id DESC LIMIT $${values.length}`, values)).rows;
  }
  async _transcript(id, state, pageLimit) {
    const values = [id]; const clauses = [visible(POSTGRES_TABLE, true), 'e.conversation_id=$1', `${field('e', 'role', true)} IN ('user','assistant')`];
    if (state) { values.push(state.t, state.s, state.e); clauses.push(`(e.source_time_key,e.source_sequence,e.event_id)<($2,$3,$4)`); }
    values.push(pageLimit);
    return (await this.pool.query(`SELECT e.event_id,${field('e', 'occurredAt', true)} occurred_at,e.source_time_key,e.source_sequence,
      ${field('e', 'role', true)} role,${field('e', 'visibleText', true)} visible_text FROM ${POSTGRES_TABLE} e WHERE ${clauses.join(' AND ')}
      ORDER BY e.source_time_key DESC,e.source_sequence DESC,e.event_id DESC LIMIT $${values.length}`, values)).rows;
  }
}
