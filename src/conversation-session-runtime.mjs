import fs from 'node:fs';
import path from 'node:path';

import { canonicalJson } from './ingest/transcripts/canonical.mjs';
import { PostgresConversationSessionView, SqliteConversationSessionView } from './conversation-session-view-v2.mjs';
import { deriveM4V3ConversationIdFromLegacySessionId } from './migration/m4-v2-conversation-projector.mjs';
import { deriveM4V3EventIdFromLegacyEventId } from './migration/m4-v2-conversation-projector.mjs';

const MODES = new Set(['disabled', 'shadow', 'active']);
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const STATUS_KEYS = ['mode', 'pending', 'compared', 'matched', 'mismatched', 'unavailable', 'inconclusive', 'skipped'];

function failure(code) { const error = new Error(code); error.code = code; return error; }
function fail(code) { throw failure(code); }
function snapshotEnv(env) {
  try {
    if (!env || typeof env !== 'object') fail('conversation_session_runtime_config_invalid');
    const keys = ['AMF_CONVERSATION_READER_MODE', 'AMF_CONVERSATION_ARCHIVE_SQLITE_PATH', 'AMF_CONVERSATION_ARCHIVE_POSTGRES_URL', 'AMF_CONVERSATION_READER_CURSOR_KEY_PATH', 'AMF_CONVERSATION_READER_SCAN_LIMIT', 'AMF_CONVERSATION_ARCHIVE_POSTGRES_SSL_MODE', 'AMF_CONVERSATION_ARCHIVE_POSTGRES_CA_PATH'];
    return Object.fromEntries(keys.map(key => [key, env[key]]));
  } catch { fail('conversation_session_runtime_config_invalid'); }
}
function requiredString(value) { return typeof value === 'string' && value.length > 0 && value.length <= 4096 && !/[\0\r\n]/.test(value); }
function regularFile(file, rootPath) {
  if (!requiredString(file)) fail('conversation_session_runtime_config_invalid');
  const resolved = path.resolve(rootPath, file);
  let stat; try { stat = fs.lstatSync(resolved); } catch { fail('conversation_session_runtime_config_invalid'); }
  if (!stat.isFile() || stat.isSymbolicLink()) fail('conversation_session_runtime_config_invalid');
  return { resolved, stat };
}
function openAnchoredRegularFile(file, rootPath, { privateMode = false, maxBytes = null } = {}) {
  const before = regularFile(file, rootPath); let fd;
  try {
    fd = fs.openSync(before.resolved, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.ino !== before.stat.ino || stat.dev !== before.stat.dev
      || (maxBytes !== null && stat.size > maxBytes)
      || (privateMode && ((stat.mode & 0o777) !== 0o600 || stat.uid !== process.getuid() || stat.nlink !== 1))) {
      fail('conversation_session_runtime_config_invalid');
    }
    return { resolved: before.resolved, fd, stat };
  } catch {
    if (fd !== undefined) try { fs.closeSync(fd); } catch {}
    fail('conversation_session_runtime_config_invalid');
  }
}
function requireAnchorPath(anchor) {
  let current; try { current = fs.lstatSync(anchor.resolved); } catch { fail('conversation_session_runtime_unavailable'); }
  if (!current.isFile() || current.isSymbolicLink() || current.ino !== anchor.stat.ino || current.dev !== anchor.stat.dev) {
    fail('conversation_session_runtime_unavailable');
  }
}
function descriptorPath(anchor) {
  const candidate = `/proc/self/fd/${anchor.fd}`;
  let stat; try { stat = fs.statSync(candidate); } catch { fail('conversation_session_runtime_unavailable'); }
  if (!stat.isFile() || stat.ino !== anchor.stat.ino || stat.dev !== anchor.stat.dev) fail('conversation_session_runtime_unavailable');
  return candidate;
}
function readAnchoredText(file, rootPath, maxBytes) {
  const anchor = openAnchoredRegularFile(file, rootPath, { maxBytes }); let raw;
  try {
    raw = Buffer.alloc(maxBytes + 1); const bytesRead = fs.readSync(anchor.fd, raw, 0, raw.length, 0); const final = fs.fstatSync(anchor.fd);
    if (bytesRead !== anchor.stat.size || final.ino !== anchor.stat.ino || final.dev !== anchor.stat.dev
      || final.size !== anchor.stat.size || final.mtimeMs !== anchor.stat.mtimeMs || final.ctimeMs !== anchor.stat.ctimeMs) {
      fail('conversation_session_runtime_config_invalid');
    }
    return raw.subarray(0, bytesRead).toString('utf8');
  } finally {
    raw?.fill(0); fs.closeSync(anchor.fd);
  }
}
function cursorKey(file, rootPath) {
  const anchor = openAnchoredRegularFile(file, rootPath, { privateMode: true, maxBytes: 128 }); let value; let raw;
  try {
    raw = Buffer.alloc(129); const bytesRead = fs.readSync(anchor.fd, raw, 0, raw.length, 0); const final = fs.fstatSync(anchor.fd);
    if (bytesRead !== anchor.stat.size || final.ino !== anchor.stat.ino || final.dev !== anchor.stat.dev || final.size !== anchor.stat.size
      || final.mtimeMs !== anchor.stat.mtimeMs || final.ctimeMs !== anchor.stat.ctimeMs || !final.isFile()
      || (final.mode & 0o777) !== 0o600 || final.uid !== process.getuid() || final.nlink !== 1) fail('conversation_session_runtime_config_invalid');
    value = raw.subarray(0, bytesRead).toString('utf8');
  } catch { fail('conversation_session_runtime_config_invalid'); }
  finally { raw?.fill(0); fs.closeSync(anchor.fd); }
  const text = value.endsWith('\n') ? value.slice(0, -1) : value;
  if (text.includes('\n') || !BASE64.test(text)) fail('conversation_session_runtime_config_invalid');
  const key = Buffer.from(text, 'base64');
  if (key.length !== 32 || key.toString('base64') !== text) { key.fill(0); fail('conversation_session_runtime_config_invalid'); }
  return key;
}
function scanLimit(value) {
  if (value == null || value === '') return 500;
  if (!/^(?:[1-9]|[1-9][0-9]{1,2})$/.test(value)) fail('conversation_session_runtime_config_invalid');
  const result = Number(value); if (result < 1 || result > 500) fail('conversation_session_runtime_config_invalid'); return result;
}
function statusSnapshot(mode, counters) { return Object.freeze(Object.fromEntries(STATUS_KEYS.map(key => [key, key === 'mode' ? mode : counters[key]]))); }
function stable(value) { return canonicalJson(value); }
function mapLegacyIdentifiers(value) {
  if (Array.isArray(value)) return value.map(mapLegacyIdentifiers);
  if (value === null || typeof value !== 'object') return value;
  const result = {};
  for (const [key, item] of Object.entries(value)) {
    if (key === 'runtime') continue;
    if ((key === 'id' || key === 'conversationId') && typeof item === 'string' && /^ses_[a-f0-9]{64}$/.test(item)) result[key] = deriveM4V3ConversationIdFromLegacySessionId(item);
    else if ((key === 'eventId' || key === 'replacesEventId' || key === 'tombstonesEventId') && typeof item === 'string' && /^evt_[a-f0-9]{64}$/.test(item)) result[key] = deriveM4V3EventIdFromLegacyEventId(item);
    else result[key] = mapLegacyIdentifiers(item);
  }
  return result;
}
function comparable(operation, value, mapLegacy) {
  const mapped = mapLegacy ? mapLegacyIdentifiers(value) : value;
  const metadata = item => {
    if (!item || typeof item !== 'object' || typeof item.id !== 'string' || typeof item.firstOccurredAt !== 'string' || typeof item.lastOccurredAt !== 'string' || !Number.isSafeInteger(item.eventCount) || typeof item.conversationKind !== 'string' || !item.contextTags || typeof item.contextTags !== 'object') throw new Error();
    return { id: item.id, firstOccurredAt: item.firstOccurredAt, lastOccurredAt: item.lastOccurredAt, eventCount: item.eventCount, conversationKind: item.conversationKind, contextTags: item.contextTags };
  };
  if (operation === 'get') return metadata(mapped);
  if (operation === 'transcript') {
    if (!mapped || typeof mapped !== 'object' || mapped.nextCursor !== null || mapped.view !== 'redacted' || !Array.isArray(mapped.items)) throw new Error();
    return { id: mapped.id, view: mapped.view, items: mapped.items.map(item => ({ eventId: item.eventId, occurredAt: item.occurredAt, role: item.role, content: item.content })) };
  }
  if (!mapped || typeof mapped !== 'object' || mapped.nextCursor !== null || !Array.isArray(mapped.items)) throw new Error();
  return { items: mapped.items.map(metadata).sort((left, right) => left.id.localeCompare(right.id)) };
}

export async function createConversationSessionRuntimeFromEnv({ env = process.env, rootPath = process.cwd(), legacyReader, dependencies = {} } = {}) {
  let mode; try { mode = env?.AMF_CONVERSATION_READER_MODE ?? 'disabled'; } catch { fail('conversation_session_runtime_config_invalid'); }
  if (!MODES.has(mode)) fail('conversation_session_runtime_config_invalid');
  if (mode === 'disabled') {
    const counters = { pending: 0, compared: 0, matched: 0, mismatched: 0, unavailable: 0, inconclusive: 0, skipped: 0 };
    const status = () => structuredClone(statusSnapshot(mode, counters));
    return { reader: null, ready: async () => undefined, close: async () => undefined, status };
  }
  const config = snapshotEnv(env);
  if (typeof rootPath !== 'string' || !path.isAbsolute(rootPath) || (!legacyReader && mode === 'shadow')) fail('conversation_session_runtime_config_invalid');
  const sqlitePath = config.AMF_CONVERSATION_ARCHIVE_SQLITE_PATH;
  const postgresUrl = config.AMF_CONVERSATION_ARCHIVE_POSTGRES_URL;
  if ((requiredString(sqlitePath) ? 1 : 0) + (requiredString(postgresUrl) ? 1 : 0) !== 1) fail('conversation_session_runtime_config_invalid');
  const key = cursorKey(config.AMF_CONVERSATION_READER_CURSOR_KEY_PATH, rootPath); const limit = scanLimit(config.AMF_CONVERSATION_READER_SCAN_LIMIT);
  let db; let pool; let reader; let sqliteAnchor;
  try {
    if (sqlitePath) {
      sqliteAnchor = openAnchoredRegularFile(sqlitePath, rootPath);
      const BetterSqlite3 = dependencies.BetterSqlite3 ?? (await import('better-sqlite3')).default;
      db = new BetterSqlite3(descriptorPath(sqliteAnchor), { readonly: true, fileMustExist: true });
      requireAnchorPath(sqliteAnchor);
      reader = new (dependencies.SqliteConversationSessionView ?? SqliteConversationSessionView)({ db, cursorKey: key, scanLimit: limit });
      for (const operation of ['get', 'transcript', 'search']) {
        const method = reader[operation].bind(reader);
        reader[operation] = async args => { requireAnchorPath(sqliteAnchor); return method(args); };
      }
    } else {
      let url; try { url = new URL(postgresUrl); } catch { fail('conversation_session_runtime_config_invalid'); }
      if (!['postgres:', 'postgresql:'].includes(url.protocol) || url.username === '' || url.hostname === '' || url.search || url.hash) fail('conversation_session_runtime_config_invalid');
      const sslMode = config.AMF_CONVERSATION_ARCHIVE_POSTGRES_SSL_MODE ?? 'verify-full';
      if (!['disable', 'require', 'verify-full'].includes(sslMode)) fail('conversation_session_runtime_config_invalid');
      if (config.AMF_CONVERSATION_ARCHIVE_POSTGRES_CA_PATH && sslMode !== 'verify-full') fail('conversation_session_runtime_config_invalid');
      let ssl = sslMode === 'disable' ? false : { rejectUnauthorized: sslMode === 'verify-full' };
      if (config.AMF_CONVERSATION_ARCHIVE_POSTGRES_CA_PATH) ssl = { rejectUnauthorized: sslMode === 'verify-full', ca: readAnchoredText(config.AMF_CONVERSATION_ARCHIVE_POSTGRES_CA_PATH, rootPath, 1_048_576) };
      const Pool = dependencies.Pool ?? (await import('pg')).Pool;
      if (typeof Pool !== 'function') fail('conversation_session_runtime_unavailable');
      pool = new Pool({ connectionString: postgresUrl, max: 4, idleTimeoutMillis: 10_000, connectionTimeoutMillis: 5_000,
        statement_timeout: 5_000, query_timeout: 5_000, options: '-c default_transaction_read_only=on', ssl });
      reader = new (dependencies.PostgresConversationSessionView ?? PostgresConversationSessionView)({ pool, cursorKey: key, scanLimit: limit });
    }
  } catch (error) { key.fill(0); try { db?.close?.(); await pool?.end?.(); if (sqliteAnchor) fs.closeSync(sqliteAnchor.fd); } catch {} if (error?.code === 'conversation_session_runtime_config_invalid') throw error; fail('conversation_session_runtime_unavailable'); }
  key.fill(0);
  const counters = { pending: 0, compared: 0, matched: 0, mismatched: 0, unavailable: 0, inconclusive: 0, skipped: 0 };
  let closed = false; const status = () => structuredClone(statusSnapshot(mode, counters));
  const ready = async () => {
    try { if (db) { requireAnchorPath(sqliteAnchor); const rows = db.prepare('PRAGMA table_info(conversation_archive_events_v1)').all(); const required = ['event_id','conversation_id','source_instance_id','state','source_occurred_at','source_time_key','source_sequence','event_json','expired']; if (!required.every(name => rows.some(row => row.name === name))) throw new Error(); requireAnchorPath(sqliteAnchor); } else await pool.query('SELECT event_id,conversation_id,source_instance_id,state,source_occurred_at,source_time_key,source_sequence,event_json,expired FROM agent_memory_fabric.conversation_archive_events_v1 WHERE false'); }
    catch { await close(); fail('conversation_session_runtime_unavailable'); }
  };
  const close = async () => { if (closed) return; closed = true; try { db?.close?.(); await pool?.end?.(); if (sqliteAnchor) fs.closeSync(sqliteAnchor.fd); } catch { fail('conversation_session_runtime_unavailable'); } };
  if (mode === 'active') { Object.defineProperty(reader, 'runtimeStatus', { value: status }); return { reader, ready, close, status }; }
  const schedule = (operation, args, primary) => {
    if (closed || counters.pending >= 4) { counters.skipped += 1; return; }
    counters.pending += 1; queueMicrotask(async () => {
      try {
        const id = args?.id; const mapped = id && /^ses_[a-f0-9]{64}$/.test(id) ? { ...args, id: deriveM4V3ConversationIdFromLegacySessionId(id) } : args;
        const right = await reader[operation](mapped);
        if ((operation === 'transcript' || operation === 'search') && (primary.nextCursor !== null || right.nextCursor !== null)) { counters.inconclusive += 1; return; }
        const leftComparable = comparable(operation, primary, true); const rightComparable = comparable(operation, right, false);
        counters.compared += 1; if (stable(leftComparable) === stable(rightComparable)) counters.matched += 1; else counters.mismatched += 1;
      } catch { counters.unavailable += 1; } finally { counters.pending -= 1; }
    });
  };
  const methods = {};
  try { for (const operation of ['get', 'transcript', 'search']) { if (typeof legacyReader[operation] !== 'function') fail('conversation_session_runtime_config_invalid'); methods[operation] = legacyReader[operation].bind(legacyReader); } } catch (error) { await close(); throw error; }
  const served = { configured: true, kind: 'conversation-archive-v3-shadow' };
  for (const operation of ['get', 'transcript', 'search']) served[operation] = async args => {
    const value = await methods[operation](args);
    try { schedule(operation, structuredClone(args), structuredClone(value)); } catch { counters.skipped += 1; }
    return value;
  };
  Object.defineProperty(served, 'runtimeStatus', { value: status });
  return { reader: served, ready, close, status };
}
