import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

import Database from 'better-sqlite3';

import { canonicalJson } from '../ingest/transcripts/canonical.mjs';
import { normalizeContextTags, normalizeSessionContextBinding, sessionContextBinding } from '../ingest/raw-projection-v2.mjs';
import {
  createM4CrossPhaseIdentityAuthority,
  createM4CrossPhaseIdentityPage,
  describeM4CrossPhaseIdentityPage,
  M4_CROSS_PHASE_IDENTITY_MAX_AUTHORITY_PAGES,
  M4_CROSS_PHASE_IDENTITY_MAX_PAGE_ENTRIES,
  M4_CROSS_PHASE_IDENTITY_MAX_TOTAL_ENTRIES,
  verifyM4CrossPhaseIdentityAuthority,
} from './m4-cross-phase-identity-registry.mjs';
import {
  deriveM4V3ConversationIdFromLegacySessionId,
  deriveM4V3EventIdFromLegacyEventId,
  deriveM4V3SourceInstanceIdFromLegacySession,
} from './m4-v2-conversation-projector.mjs';
import { createM4CrossPhaseIdentityZeroStreamingCoverage, verifyM4CrossPhaseIdentityTraversalCompletion } from './m4-cross-phase-identity-traversal-completion.mjs';

export const M4_CROSS_PHASE_IDENTITY_STREAMING_BLOCK_SCHEMA = 'amf.m4-cross-phase-projector-identity-block/v1';
export const M4_CROSS_PHASE_IDENTITY_STREAMING_MAX_PAGE_BYTES = 8 * 1024 * 1024;
export const M4_CROSS_PHASE_IDENTITY_STREAMING_MIN_AVAILABLE_BYTES = 5 * 1024 * 1024 * 1024;
export const M4_CROSS_PHASE_IDENTITY_STREAMING_RECOMMENDED_AVAILABLE_BYTES = 8 * 1024 * 1024 * 1024;

const SESSION_ID = /^ses_[a-f0-9]{64}$/;
const EVENT_ID = /^evt_[a-f0-9]{64}$/;
const CONVERSATION_ID = /^ccon_[a-z0-9][a-z0-9_-]{7,127}$/;
const SOURCE_INSTANCE_ID = /^src_[a-z0-9][a-z0-9_-]{7,127}$/;
const SOURCE_TAG = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}:[a-f0-9]{64}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const KEY_ID = /^[a-z][a-z0-9-]{2,79}$/;
const B64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const KINDS = new Set(['dm', 'group', 'channel', 'thread', 'session', 'unknown']);
const ROLES = new Set(['user', 'assistant']);
const DIRECTIONS = new Set(['inbound', 'outbound']);
const STATES = new Set(['active', 'edited', 'replacement', 'tombstone', 'conflict']);
const GIB = 1024 * 1024 * 1024;

function fail(code) { const error = new Error(code); error.code = code; throw error; }
function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function exact(value, keys) { return plain(value) && Object.keys(value).sort().join('\0') === [...keys].sort().join('\0'); }
function clone(value, code) { try { return structuredClone(value); } catch { fail(code); } }
function digest(value) { return `sha256:${crypto.createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`; }
function safeEqual(left, right) { const a = Buffer.from(String(left), 'utf8'); const b = Buffer.from(String(right), 'utf8'); return a.length === b.length && crypto.timingSafeEqual(a, b); }
function completionKeyMaterial(value) { const safe = clone(value, 'm4_cross_phase_identity_streaming_completion_key_invalid'); if (!exact(safe, ['schema','keyId','key']) || safe.schema !== 'amf.migration-signing-key/v1' || !KEY_ID.test(safe.keyId) || typeof safe.key !== 'string' || !B64.test(safe.key)) fail('m4_cross_phase_identity_streaming_completion_key_invalid'); const material = Buffer.from(safe.key,'base64'); if (material.length < 32 || material.length > 64 || material.toString('base64') !== safe.key) { material.fill(0); fail('m4_cross_phase_identity_streaming_completion_key_invalid'); } return material; }
function registryCommitment(registrySecret, registryKeyId) { return `hmac-sha256:${crypto.createHmac('sha256', registrySecret).update(canonicalJson(['amf.m4-cross-phase-identity-traversal-completion/v1/registry-key', registryKeyId]), 'utf8').digest('base64url')}`; }
function privateMode(stat) { return stat.uid === process.getuid() && (stat.mode & 0o077) === 0; }
function canonicalBytes(value) { return Buffer.byteLength(canonicalJson(value), 'utf8'); }
function bucketFor(value, prefix) { return value.slice(prefix.length, prefix.length + 2); }

function sourceTags(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 64
    || value.some(item => typeof item !== 'string' || !SOURCE_TAG.test(item))) fail('m4_cross_phase_identity_streaming_block_invalid');
  const result = [...value];
  for (let index = 1; index < result.length; index += 1) if (result[index - 1] >= result[index]) fail('m4_cross_phase_identity_streaming_block_invalid');
  return result;
}
function session(value) {
  if (!exact(value, ['legacySessionId', 'conversationId', 'conversationKind', 'sessionContextTags'])
    || !SESSION_ID.test(value.legacySessionId) || !CONVERSATION_ID.test(value.conversationId) || !KINDS.has(value.conversationKind)) {
    fail('m4_cross_phase_identity_streaming_block_invalid');
  }
  let sessionContextTags;
  try { sessionContextTags = normalizeSessionContextBinding(value.sessionContextTags); }
  catch { fail('m4_cross_phase_identity_streaming_block_invalid'); }
  if (deriveM4V3ConversationIdFromLegacySessionId(value.legacySessionId) !== value.conversationId) fail('m4_cross_phase_identity_streaming_binding_invalid');
  return { legacySessionId: value.legacySessionId, conversationId: value.conversationId, conversationKind: value.conversationKind, sessionContextTags };
}
function event(value, owner) {
  const keys = ['legacyEventId', 'legacySessionId', 'eventId', 'conversationId', 'sourceInstanceId', 'sourceTags',
    'conversationKind', 'authorizationContextTags', 'role', 'direction', 'state', 'revision',
    'replacesLegacyEventId', 'tombstonesLegacyEventId', 'conflictsWithLegacyEventIds'];
  if (!exact(value, keys) || !EVENT_ID.test(value.legacyEventId) || !SESSION_ID.test(value.legacySessionId)
    || !CONVERSATION_ID.test(value.conversationId) || !SOURCE_INSTANCE_ID.test(value.sourceInstanceId)
    || !KINDS.has(value.conversationKind) || !ROLES.has(value.role) || !DIRECTIONS.has(value.direction)
    || !STATES.has(value.state) || !Number.isSafeInteger(value.revision) || value.revision < 1
    || !(value.replacesLegacyEventId === null || EVENT_ID.test(value.replacesLegacyEventId))
    || !(value.tombstonesLegacyEventId === null || EVENT_ID.test(value.tombstonesLegacyEventId))
    || !Array.isArray(value.conflictsWithLegacyEventIds) || value.conflictsWithLegacyEventIds.length > 32
    || value.conflictsWithLegacyEventIds.some(item => typeof item !== 'string' || !EVENT_ID.test(item))) fail('m4_cross_phase_identity_streaming_block_invalid');
  if (new Set(value.conflictsWithLegacyEventIds).size !== value.conflictsWithLegacyEventIds.length
    || value.conflictsWithLegacyEventIds.some((item, index) => index > 0 && value.conflictsWithLegacyEventIds[index - 1] >= item)
    || (value.state === 'active' && (value.revision !== 1 || value.replacesLegacyEventId !== null || value.tombstonesLegacyEventId !== null || value.conflictsWithLegacyEventIds.length))
    || (['edited', 'replacement'].includes(value.state) && (value.revision < 2 || value.replacesLegacyEventId === null || value.tombstonesLegacyEventId !== null || value.conflictsWithLegacyEventIds.length))
    || (value.state === 'tombstone' && (value.replacesLegacyEventId !== null || value.tombstonesLegacyEventId === null || value.conflictsWithLegacyEventIds.length))
    || (value.state === 'conflict' && (value.replacesLegacyEventId !== null || value.tombstonesLegacyEventId !== null || value.conflictsWithLegacyEventIds.length < 1))) {
    fail('m4_cross_phase_identity_streaming_block_invalid');
  }
  const tags = sourceTags(value.sourceTags); let authorizationContextTags; let eventSessionContextTags;
  try { authorizationContextTags = normalizeContextTags(value.authorizationContextTags); eventSessionContextTags = sessionContextBinding(authorizationContextTags); }
  catch { fail('m4_cross_phase_identity_streaming_block_invalid'); }
  if (value.legacySessionId !== owner.legacySessionId || value.conversationId !== owner.conversationId
    || value.conversationKind !== owner.conversationKind || canonicalJson(eventSessionContextTags) !== canonicalJson(owner.sessionContextTags)
    || deriveM4V3EventIdFromLegacyEventId(value.legacyEventId) !== value.eventId
    || deriveM4V3ConversationIdFromLegacySessionId(value.legacySessionId) !== value.conversationId
    || deriveM4V3SourceInstanceIdFromLegacySession(value.legacySessionId, tags) !== value.sourceInstanceId) {
    fail('m4_cross_phase_identity_streaming_binding_invalid');
  }
  return { legacyEventId: value.legacyEventId, legacySessionId: value.legacySessionId, eventId: value.eventId,
    conversationId: value.conversationId, sourceInstanceId: value.sourceInstanceId, sourceTags: tags,
    conversationKind: value.conversationKind, authorizationContextTags, role: value.role, direction: value.direction,
    state: value.state, revision: value.revision, replacesLegacyEventId: value.replacesLegacyEventId,
    tombstonesLegacyEventId: value.tombstonesLegacyEventId, conflictsWithLegacyEventIds: [...value.conflictsWithLegacyEventIds] };
}
function block(value) {
  const input = clone(value, 'm4_cross_phase_identity_streaming_block_invalid');
  if (!exact(input, ['schema', 'session', 'events']) || input.schema !== M4_CROSS_PHASE_IDENTITY_STREAMING_BLOCK_SCHEMA
    || !Array.isArray(input.events) || input.events.length < 1 || input.events.length > 34) fail('m4_cross_phase_identity_streaming_block_invalid');
  const safeSession = session(input.session);
  const events = input.events.map(item => event(item, safeSession)).sort((left, right) => left.legacyEventId.localeCompare(right.legacyEventId));
  if (new Set(events.map(item => item.legacyEventId)).size !== events.length) fail('m4_cross_phase_identity_streaming_block_invalid');
  return { schema: M4_CROSS_PHASE_IDENTITY_STREAMING_BLOCK_SCHEMA, session: safeSession, events };
}
function capacityInput(value) {
  if (!exact(value, ['sampleBlocks', 'expectedBlockCount']) || !Array.isArray(value.sampleBlocks)
    || value.sampleBlocks.length < 1 || value.sampleBlocks.length > 10_000
    || !Number.isSafeInteger(value.expectedBlockCount) || value.expectedBlockCount < value.sampleBlocks.length) {
    fail('m4_cross_phase_identity_capacity_request_invalid');
  }
  return value;
}

// The estimate intentionally over-allocates for B-trees, DELETE-mode journals,
// temporary SQL work, and page construction. It contains only counts and bytes.
export function estimateM4CrossPhaseIdentityStreamingCapacity(input = {}) {
  const safe = capacityInput(clone(input, 'm4_cross_phase_identity_capacity_request_invalid'));
  let sampleEntries = 0; let sampleBytes = 0;
  for (const item of safe.sampleBlocks) {
    const safeBlock = block(item); sampleEntries += 1 + safeBlock.events.length; sampleBytes += canonicalBytes(safeBlock);
  }
  const estimatedPayloadBytes = Math.ceil((sampleBytes / safe.sampleBlocks.length) * safe.expectedBlockCount);
  const estimatedBytes = Math.ceil(estimatedPayloadBytes * 1.45) + (64 * 1024 * 1024);
  const requiredAvailableBytes = Math.max(M4_CROSS_PHASE_IDENTITY_STREAMING_MIN_AVAILABLE_BYTES, Math.ceil(estimatedBytes * 3.5) + GIB);
  return Object.freeze({ sampleBlockCount: safe.sampleBlocks.length, sampleEntryCount: sampleEntries,
    expectedBlockCount: safe.expectedBlockCount, estimatedBytes, requiredAvailableBytes,
    recommendedAvailableBytes: M4_CROSS_PHASE_IDENTITY_STREAMING_RECOMMENDED_AVAILABLE_BYTES });
}

export function preflightM4CrossPhaseIdentityStreamingCapacity({ availableBytes, ...input } = {}) {
  if (!Number.isSafeInteger(availableBytes) || availableBytes < 0) fail('m4_cross_phase_identity_capacity_request_invalid');
  const estimate = estimateM4CrossPhaseIdentityStreamingCapacity(input);
  if (availableBytes < estimate.requiredAvailableBytes) fail('m4_cross_phase_identity_capacity_insufficient');
  return Object.freeze({ ...estimate, availableBytes });
}

function ensurePrivateDirectory(directory) {
  if (!path.isAbsolute(directory)) fail('m4_cross_phase_identity_streaming_path_invalid');
  const parsed = path.parse(directory); const segments = directory.slice(parsed.root.length).split(path.sep).filter(Boolean);
  let current = parsed.root;
  for (const segment of segments) {
    current = path.join(current, segment);
    let stat;
    try { stat = fs.lstatSync(current); }
    catch (error) {
      if (error?.code !== 'ENOENT') fail('m4_cross_phase_identity_streaming_resource_unsafe');
      try { fs.mkdirSync(current, { mode: 0o700 }); stat = fs.lstatSync(current); }
      catch { fail('m4_cross_phase_identity_streaming_resource_unsafe'); }
    }
    if (stat.isSymbolicLink() || !stat.isDirectory()) fail('m4_cross_phase_identity_streaming_resource_unsafe');
  }
  const stat = fs.lstatSync(directory);
  if (!privateMode(stat)) fail('m4_cross_phase_identity_streaming_resource_unsafe');
  return { path: directory, dev: stat.dev, ino: stat.ino };
}
function readPrivateDirectory(directory) {
  if (!path.isAbsolute(directory) || path.resolve(directory) !== directory) fail('m4_cross_phase_identity_streaming_resource_unsafe');
  const parsed = path.parse(directory); const segments = directory.slice(parsed.root.length).split(path.sep).filter(Boolean); let current = parsed.root;
  for (const segment of segments) { current = path.join(current, segment); let stat; try { stat = fs.lstatSync(current); } catch { fail('m4_cross_phase_identity_streaming_resource_unsafe'); } if (stat.isSymbolicLink() || !stat.isDirectory()) fail('m4_cross_phase_identity_streaming_resource_unsafe'); }
  const stat = fs.lstatSync(directory); if (!privateMode(stat)) fail('m4_cross_phase_identity_streaming_resource_unsafe'); return { path:directory, dev:stat.dev, ino:stat.ino };
}
function openPinnedDirectory(anchor) {
  let fd; try { fd = fs.openSync(anchor.path, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW); }
  catch { fail('m4_cross_phase_identity_streaming_resource_unsafe'); }
  let stat; try { stat = fs.fstatSync(fd); } catch { try { fs.closeSync(fd); } catch {} fail('m4_cross_phase_identity_streaming_resource_unsafe'); }
  if (!stat.isDirectory() || !privateMode(stat) || stat.dev !== anchor.dev || stat.ino !== anchor.ino) {
    try { fs.closeSync(fd); } catch {} fail('m4_cross_phase_identity_streaming_resource_unsafe');
  }
  return { ...anchor, fd };
}
function assertDirectory(anchor) {
  let stat; try { stat = fs.fstatSync(anchor.fd); } catch { fail('m4_cross_phase_identity_streaming_resource_unsafe'); }
  if (stat.isSymbolicLink() || !stat.isDirectory() || !privateMode(stat) || stat.dev !== anchor.dev || stat.ino !== anchor.ino) {
    fail('m4_cross_phase_identity_streaming_resource_unsafe');
  }
}
function assertFile(filename, anchor) {
  assertDirectory(anchor); let stat; try { stat = fs.lstatSync(filename); } catch { fail('m4_cross_phase_identity_streaming_resource_unsafe'); }
  if (stat.isSymbolicLink() || !stat.isFile() || !privateMode(stat)) fail('m4_cross_phase_identity_streaming_resource_unsafe');
  return { dev: stat.dev, ino: stat.ino };
}
function assertPinnedFile(filename, anchor, expected) {
  const actual = assertFile(filename, anchor);
  if (actual.dev !== expected.dev || actual.ino !== expected.ino) fail('m4_cross_phase_identity_streaming_resource_unsafe');
}
function databaseSchema(db) {
  db.pragma('journal_mode = DELETE'); db.pragma('synchronous = FULL'); db.pragma('temp_store = FILE'); db.pragma('cache_size = -8192');
  db.exec(`CREATE TABLE IF NOT EXISTS m4_stream_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS m4_stream_blocks (block_digest TEXT PRIMARY KEY) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS m4_stream_sessions (legacy_session_id TEXT PRIMARY KEY, bucket TEXT NOT NULL, payload TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS m4_stream_events (legacy_event_id TEXT PRIMARY KEY, bucket TEXT NOT NULL, legacy_session_id TEXT NOT NULL, conversation_id TEXT NOT NULL, source_instance_id TEXT NOT NULL, payload TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS m4_stream_references (legacy_event_id TEXT NOT NULL, target_legacy_event_id TEXT NOT NULL, PRIMARY KEY (legacy_event_id, target_legacy_event_id)) WITHOUT ROWID;
INSERT OR IGNORE INTO m4_stream_meta(key,value) VALUES ('schema_version','2');
INSERT OR IGNORE INTO m4_stream_meta(key,value) VALUES ('accepted_blocks','0');`);
}
const TABLES = new Set(['m4_stream_meta', 'm4_stream_blocks', 'm4_stream_sessions', 'm4_stream_events', 'm4_stream_references']);
const META_KEYS = new Set(['schema_version', 'accepted_blocks', 'expected_block_count', 'seal_binding', 'seal_completion_digest', 'sealed_result']);
const TABLE_SQL = new Map([
  ['m4_stream_meta', 'CREATE TABLE m4_stream_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID'],
  ['m4_stream_blocks', 'CREATE TABLE m4_stream_blocks (block_digest TEXT PRIMARY KEY) WITHOUT ROWID'],
  ['m4_stream_sessions', 'CREATE TABLE m4_stream_sessions (legacy_session_id TEXT PRIMARY KEY, bucket TEXT NOT NULL, payload TEXT NOT NULL) WITHOUT ROWID'],
  ['m4_stream_events', 'CREATE TABLE m4_stream_events (legacy_event_id TEXT PRIMARY KEY, bucket TEXT NOT NULL, legacy_session_id TEXT NOT NULL, conversation_id TEXT NOT NULL, source_instance_id TEXT NOT NULL, payload TEXT NOT NULL) WITHOUT ROWID'],
  ['m4_stream_references', 'CREATE TABLE m4_stream_references (legacy_event_id TEXT NOT NULL, target_legacy_event_id TEXT NOT NULL, PRIMARY KEY (legacy_event_id, target_legacy_event_id)) WITHOUT ROWID'],
]);
const COLUMNS = new Map([
  ['m4_stream_meta', [['key', 'TEXT', 1, 1], ['value', 'TEXT', 1, 0]]], ['m4_stream_blocks', [['block_digest', 'TEXT', 1, 1]]],
  ['m4_stream_sessions', [['legacy_session_id', 'TEXT', 1, 1], ['bucket', 'TEXT', 1, 0], ['payload', 'TEXT', 1, 0]]],
  ['m4_stream_events', [['legacy_event_id', 'TEXT', 1, 1], ['bucket', 'TEXT', 1, 0], ['legacy_session_id', 'TEXT', 1, 0], ['conversation_id', 'TEXT', 1, 0], ['source_instance_id', 'TEXT', 1, 0], ['payload', 'TEXT', 1, 0]]],
  ['m4_stream_references', [['legacy_event_id', 'TEXT', 1, 1], ['target_legacy_event_id', 'TEXT', 1, 2]]],
]);
function validateSchema(db) {
  const objects = db.prepare("SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name").all();
  if (objects.length !== TABLES.size || objects.some(item => item.type !== 'table' || !TABLES.has(item.name)
    || typeof item.sql !== 'string' || item.sql.trim().replace(/\s+/g, ' ').toLowerCase() !== TABLE_SQL.get(item.name).toLowerCase())) fail('m4_cross_phase_identity_streaming_state_invalid');
  for (const [table, expected] of COLUMNS) {
    const columns = db.prepare(`PRAGMA table_info(${table})`).all().map(item => [item.name, item.type, item.notnull, item.pk]);
    if (canonicalJson(columns) !== canonicalJson(expected)) fail('m4_cross_phase_identity_streaming_state_invalid');
  }
  const values = new Map(db.prepare('SELECT key,value FROM m4_stream_meta').all().map(item => [item.key, item.value]));
  if ([...values.keys()].some(key => !META_KEYS.has(key)) || !['1', '2'].includes(values.get('schema_version'))
    || !/^(0|[1-9][0-9]*)$/.test(values.get('accepted_blocks') ?? '')
    || !Number.isSafeInteger(Number(values.get('accepted_blocks')))) fail('m4_cross_phase_identity_streaming_state_invalid');
  if (values.has('expected_block_count') && (!/^[1-9][0-9]*$/.test(values.get('expected_block_count')) || !Number.isSafeInteger(Number(values.get('expected_block_count'))))) {
    fail('m4_cross_phase_identity_streaming_state_invalid');
  }
  if (values.get('schema_version') === '2') {
    const count = db.prepare('SELECT count(*) AS count FROM m4_stream_blocks').get()?.count;
    if (!Number.isSafeInteger(count) || count < 0 || Number(values.get('accepted_blocks')) !== count) {
      fail('m4_cross_phase_identity_streaming_state_invalid');
    }
  }
  return values;
}
function migrateLegacyMeta(db) {
  const values = validateSchema(db);
  if (values.get('schema_version') !== '1') return values;
  if (['seal_binding', 'seal_completion_digest', 'sealed_result'].some(key => values.has(key))) {
    fail('m4_cross_phase_identity_streaming_state_invalid');
  }
  try {
    db.transaction(() => {
      const count = db.prepare('SELECT count(*) AS count FROM m4_stream_blocks').get()?.count;
      if (!Number.isSafeInteger(count) || count < 0) fail('m4_cross_phase_identity_streaming_state_invalid');
      db.prepare("UPDATE m4_stream_meta SET value=? WHERE key='accepted_blocks'").run(String(count));
      db.prepare("UPDATE m4_stream_meta SET value='2' WHERE key='schema_version'").run();
    }).immediate();
  } catch (error) {
    if (error?.code === 'm4_cross_phase_identity_streaming_state_invalid') throw error;
    fail('m4_cross_phase_identity_streaming_state_invalid');
  }
  return validateSchema(db);
}
function bucketAt(index) { return index.toString(16).padStart(2, '0'); }

// Read-only inspection for a later trusted completion stage. It never creates
// a directory, database, journal, row, or page.
export function readM4CrossPhaseIdentityStreamingCoverage({ databasePath } = {}) {
  if (typeof databasePath !== 'string' || !path.isAbsolute(databasePath) || path.resolve(databasePath) !== databasePath) fail('m4_cross_phase_identity_streaming_request_invalid');
  const directory = path.dirname(databasePath); const anchor = openPinnedDirectory(readPrivateDirectory(directory)); const pinnedPath = `/proc/self/fd/${anchor.fd}/${path.basename(databasePath)}`;
  let db;
  try {
    const before = assertFile(pinnedPath, anchor); db = new Database(pinnedPath, { readonly: true, fileMustExist: true }); assertPinnedFile(pinnedPath, anchor, before);
    const meta = validateSchema(db); const expected = Number(meta.get('expected_block_count'));
    if (!Number.isSafeInteger(expected) || expected < 1) fail('m4_cross_phase_identity_streaming_state_invalid');
    const hasBinding = meta.has('seal_binding'); const hasCompletion = meta.has('seal_completion_digest'); const hasResult = meta.has('sealed_result');
    if (hasBinding !== hasCompletion || (hasResult && !hasBinding)) fail('m4_cross_phase_identity_streaming_state_invalid');
    const counts = db.prepare('SELECT (SELECT count(*) FROM m4_stream_blocks) AS blockCount,(SELECT count(*) FROM m4_stream_sessions) AS sessionCount,(SELECT count(*) FROM m4_stream_events) AS eventCount').get();
    if (![counts.blockCount, counts.sessionCount, counts.eventCount].every(value => Number.isSafeInteger(value) && value >= 0)) fail('m4_cross_phase_identity_streaming_state_invalid');
    const state = hasResult ? 'sealed' : hasBinding ? 'seal-intent' : 'open';
    return Object.freeze({ schema: 'amf.m4-cross-phase-identity-streaming-coverage/v1', state, expectedBlockCount: expected, blockCount: counts.blockCount, sessionCount: counts.sessionCount, eventCount: counts.eventCount });
  } catch (error) { if (typeof error?.code === 'string' && error.code.startsWith('m4_cross_phase_identity_')) throw error; fail('m4_cross_phase_identity_streaming_state_invalid'); }
  finally { try { db?.close(); } catch {} try { fs.closeSync(anchor.fd); } catch {} }
}
function bucketRange(prefix, bucketIndex, cursor) {
  const bucket = bucketAt(bucketIndex); const lower = cursor || `${prefix}${bucket}`;
  const upper = bucketIndex === 255 ? `${prefix}g` : `${prefix}${bucketAt(bucketIndex + 1)}`;
  return { bucket, lower, upper };
}
function pageLimit(entries, bucket, entryKind, shard) {
  let lower = 1; let upper = Math.min(entries.length, M4_CROSS_PHASE_IDENTITY_MAX_PAGE_ENTRIES); let accepted = null;
  while (lower <= upper) {
    const size = Math.floor((lower + upper) / 2);
    let page;
    try { page = createM4CrossPhaseIdentityPage({ bucket, entryKind, shard, entries: entries.slice(0, size) }); }
    catch (error) { throw error; }
    if (canonicalBytes(page) <= M4_CROSS_PHASE_IDENTITY_STREAMING_MAX_PAGE_BYTES) { accepted = page; lower = size + 1; }
    else upper = size - 1;
  }
  if (accepted === null) fail('m4_cross_phase_identity_streaming_page_byte_limit');
  return accepted;
}
function pageAck(value, page) {
  if (!exact(value, ['pageKey', 'digest']) || value.pageKey !== page.pageKey || value.digest !== page.digest) {
    fail('m4_cross_phase_identity_streaming_page_ack_invalid');
  }
}

export function createM4CrossPhaseIdentityEmptyRegistry(input = {}) {
  const safe = clone(input, 'm4_cross_phase_identity_empty_registry_input_invalid');
  if (!exact(safe, ['traversalCompletion','completionKeyDocument','registrySecret','registryKeyId']) || typeof safe.registryKeyId !== 'string' || !KEY_ID.test(safe.registryKeyId) || !(safe.registrySecret instanceof Uint8Array) || safe.registrySecret.byteLength !== 32) fail('m4_cross_phase_identity_empty_registry_input_invalid');
  const registrySecret = Buffer.from(safe.registrySecret); let completionMaterial;
  try {
    completionMaterial = completionKeyMaterial(safe.completionKeyDocument);
    const completion = verifyM4CrossPhaseIdentityTraversalCompletion(safe.traversalCompletion, safe.completionKeyDocument);
    if (canonicalJson(completion.coverage) !== canonicalJson(createM4CrossPhaseIdentityZeroStreamingCoverage())) fail('m4_cross_phase_identity_empty_registry_coverage_invalid');
    if (completion.registryKeyId !== safe.registryKeyId) fail('m4_cross_phase_identity_empty_registry_binding_invalid');
    const left = Buffer.alloc(64); const right = Buffer.alloc(64);
    try { completionMaterial.copy(left); registrySecret.copy(right); if (safe.completionKeyDocument.keyId === safe.registryKeyId || crypto.timingSafeEqual(left,right)) fail('m4_cross_phase_identity_empty_registry_key_separation_invalid'); }
    finally { left.fill(0); right.fill(0); }
    if (!safeEqual(completion.registryKeyCommitment, registryCommitment(registrySecret,safe.registryKeyId))) fail('m4_cross_phase_identity_empty_registry_binding_invalid');
    const authority = createM4CrossPhaseIdentityAuthority({ coveredThrough:completion.coveredThrough, backfillBinding:completion.archiveBinding, pageDescriptors:[] }, registrySecret);
    return Object.freeze({ authority, coverage:Object.freeze({ acceptedBlockCount:0, sessionCount:0, eventCount:0, pageCount:0 }) });
  } finally { completionMaterial?.fill(0); registrySecret.fill(0); safe.registrySecret.fill(0); }
}

export function createM4CrossPhaseIdentityStreamingWriter({ databasePath, registrySecret, registryKeyId, capacityPreflight, pageSink } = {}) {
  if (typeof databasePath !== 'string' || !path.isAbsolute(databasePath) || path.resolve(databasePath) !== databasePath
    || path.basename(databasePath) !== databasePath.split(path.sep).at(-1)
    || !Buffer.isBuffer(registrySecret) || registrySecret.length !== 32
    || typeof registryKeyId !== 'string' || !KEY_ID.test(registryKeyId)
    || !exact(pageSink, ['writePage'])) fail('m4_cross_phase_identity_streaming_request_invalid');
  const writePage = pageSink.writePage;
  if (typeof writePage !== 'function') fail('m4_cross_phase_identity_streaming_request_invalid');
  const preflight = preflightM4CrossPhaseIdentityStreamingCapacity(capacityPreflight);
  let secret = Buffer.from(registrySecret); let parent = ensurePrivateDirectory(path.dirname(databasePath)); parent = openPinnedDirectory(parent);
  const basename = path.basename(databasePath); const pinnedPath = `/proc/self/fd/${parent.fd}/${basename}`;
  let existed = false; let existingSize = 0;
  try { const stat = fs.lstatSync(pinnedPath); existed = true; existingSize = stat.size; assertFile(pinnedPath, parent); }
  catch (error) { if (error?.code !== 'ENOENT') { try { fs.closeSync(parent.fd); } catch {} fail('m4_cross_phase_identity_streaming_resource_unsafe'); } }
  try {
    if (!existed) { const fd = fs.openSync(pinnedPath, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY | fs.constants.O_NOFOLLOW, 0o600); fs.closeSync(fd); }
  } catch { try { fs.closeSync(parent.fd); } catch {} fail('m4_cross_phase_identity_streaming_resource_unsafe'); }
  let db;
  try {
    const fileBeforeOpen = assertFile(pinnedPath, parent);
    if (existed && existingSize > 0) {
      const probe = new Database(pinnedPath, { readonly: true, fileMustExist: true });
      try { assertPinnedFile(pinnedPath, parent, fileBeforeOpen); validateSchema(probe); } finally { probe.close(); }
      db = new Database(pinnedPath, { fileMustExist: true }); assertPinnedFile(pinnedPath, parent, fileBeforeOpen);
      db.pragma('journal_mode = DELETE'); db.pragma('synchronous = FULL'); db.pragma('temp_store = FILE'); db.pragma('cache_size = -8192');
    } else {
      db = new Database(pinnedPath, { fileMustExist: true }); assertPinnedFile(pinnedPath, parent, fileBeforeOpen); databaseSchema(db); fs.chmodSync(pinnedPath, 0o600);
    }
  } catch { try { db?.close(); fs.closeSync(parent.fd); } catch {} fail('m4_cross_phase_identity_streaming_resource_unsafe'); }
  function abortConstructor(code) { try { db?.close(); } catch {} try { fs.closeSync(parent.fd); } catch {} fail(code); }
  let file; try { file = assertFile(pinnedPath, parent); } catch { abortConstructor('m4_cross_phase_identity_streaming_resource_unsafe'); }
  let meta;
  try { meta = migrateLegacyMeta(db); } catch { try { db.close(); fs.closeSync(parent.fd); } catch {} fail('m4_cross_phase_identity_streaming_state_invalid'); }
  let setMeta; let initialMeta;
  try {
    setMeta = db.prepare('INSERT INTO m4_stream_meta(key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value');
    const expectedStored = meta.get('expected_block_count');
    if (expectedStored === undefined) setMeta.run('expected_block_count', String(preflight.expectedBlockCount));
    else if (expectedStored !== String(preflight.expectedBlockCount)) fail('m4_cross_phase_identity_streaming_state_invalid');
    initialMeta = validateSchema(db);
  } catch { abortConstructor('m4_cross_phase_identity_streaming_state_invalid'); }
  let sealedBinding = initialMeta.get('seal_binding') ?? null; let sealCompletionDigest = initialMeta.get('seal_completion_digest') ?? null; let sealedResult = initialMeta.get('sealed_result') ?? null;
  if (!(sealedBinding === null || typeof sealedBinding === 'string') || !(sealedResult === null || typeof sealedResult === 'string')
    || !(sealCompletionDigest === null || DIGEST.test(sealCompletionDigest)) || (sealedResult !== null && (sealedBinding === null || sealCompletionDigest === null))
    || (sealedBinding !== null && sealCompletionDigest === null) || (sealedBinding === null && sealCompletionDigest !== null)) abortConstructor('m4_cross_phase_identity_streaming_state_invalid');
  let closed = false; let sealing = false; let sealed = sealedResult !== null;
  if (sealed) {
    try {
      const parsed = JSON.parse(sealedResult); const authority = verifyM4CrossPhaseIdentityAuthority(parsed.authority, secret);
      if (!exact(parsed, ['authority', 'coverage']) || !exact(parsed.coverage, ['acceptedBlockCount', 'sessionCount', 'eventCount', 'pageCount'])
        || !Number.isSafeInteger(parsed.coverage.acceptedBlockCount) || parsed.coverage.acceptedBlockCount < 0
        || parsed.coverage.sessionCount !== authority.coverage.sessionCount || parsed.coverage.eventCount !== authority.coverage.eventCount
        || parsed.coverage.pageCount !== authority.pages.length || parsed.coverage.acceptedBlockCount !== Number(initialMeta.get('accepted_blocks'))
        || sealedBinding !== canonicalJson({ coveredThrough: authority.coveredThrough, backfillBinding: authority.backfillBinding, completionDigest: sealCompletionDigest })) fail('m4_cross_phase_identity_streaming_state_invalid');
      secret.fill(0); secret = null;
    } catch { try { db.close(); fs.closeSync(parent.fd); } catch {} fail('m4_cross_phase_identity_streaming_state_invalid'); }
  }
  function statement(sql) { try { return db.prepare(sql); } catch { abortConstructor('m4_cross_phase_identity_streaming_state_invalid'); } }
  const get = statement('SELECT payload FROM m4_stream_sessions WHERE legacy_session_id=?');
  const getEvent = statement('SELECT payload FROM m4_stream_events WHERE legacy_event_id=?');
  const getBlock = statement('SELECT 1 FROM m4_stream_blocks WHERE block_digest=?');
  const insertSession = statement('INSERT INTO m4_stream_sessions(legacy_session_id,bucket,payload) VALUES (?,?,?)');
  const insertEvent = statement('INSERT INTO m4_stream_events(legacy_event_id,bucket,legacy_session_id,conversation_id,source_instance_id,payload) VALUES (?,?,?,?,?,?)');
  const insertReference = statement('INSERT INTO m4_stream_references(legacy_event_id,target_legacy_event_id) VALUES (?,?)');
  const insertBlock = statement('INSERT INTO m4_stream_blocks(block_digest) VALUES (?)');
  const incrementAccepted = statement("UPDATE m4_stream_meta SET value=CAST(value AS INTEGER)+1 WHERE key='accepted_blocks'");
  const acceptedCount = statement("SELECT value FROM m4_stream_meta WHERE key='accepted_blocks'");
  const counts = statement('SELECT (SELECT count(*) FROM m4_stream_blocks) AS blocks, (SELECT count(*) FROM m4_stream_sessions) AS sessions, (SELECT count(*) FROM m4_stream_events) AS events');
  const getMeta = statement('SELECT value FROM m4_stream_meta WHERE key=?');
  const persistSealIntent = db.transaction((binding, completionDigest, signedCoverage) => {
    const expectedBlockCount = getMeta.get('expected_block_count')?.value; const durableCounts = counts.get();
    const expectedCoverage = { schema: 'amf.m4-cross-phase-identity-streaming-coverage/v1', state: signedCoverage.state,
      expectedBlockCount: Number(expectedBlockCount), blockCount: durableCounts.blocks, sessionCount: durableCounts.sessions, eventCount: durableCounts.events };
    if (!Number.isSafeInteger(expectedCoverage.expectedBlockCount) || expectedCoverage.expectedBlockCount < 1) fail('m4_cross_phase_identity_streaming_state_invalid');
    if (canonicalJson(signedCoverage) !== canonicalJson(expectedCoverage)) fail('m4_cross_phase_identity_streaming_completion_coverage_mismatch');
    const storedBinding = getMeta.get('seal_binding')?.value ?? null; const storedDigest = getMeta.get('seal_completion_digest')?.value ?? null;
    if ((storedBinding === null) !== (storedDigest === null)) fail('m4_cross_phase_identity_streaming_state_invalid');
    if (storedBinding !== null) {
      if (storedBinding !== binding || storedDigest !== completionDigest) fail('m4_cross_phase_identity_streaming_seal_binding_invalid');
      return { binding: storedBinding, completionDigest: storedDigest };
    }
    setMeta.run('seal_binding', binding); setMeta.run('seal_completion_digest', completionDigest);
    return { binding, completionDigest };
  }).immediate;
  function assertOpen() { if (closed) fail('m4_cross_phase_identity_streaming_closed'); assertPinnedFile(pinnedPath, parent, file); }
  const writeBlock = db.transaction(safeBlock => {
    const blockDigest = digest(safeBlock);
    if (getBlock.get(blockDigest)) return { blockDigest, accepted: false };
    if (getMeta.get('seal_binding')) fail('m4_cross_phase_identity_streaming_sealed');
    const current = counts.get();
    if (current.blocks >= preflight.expectedBlockCount) fail('m4_cross_phase_identity_streaming_bounds_exceeded');
    const knownSession = get.get(safeBlock.session.legacySessionId);
    const sessionPayload = canonicalJson(safeBlock.session);
    if (knownSession && knownSession.payload !== sessionPayload) fail('m4_cross_phase_identity_streaming_session_drift');
    for (const item of safeBlock.events) {
      const known = getEvent.get(item.legacyEventId); const payload = canonicalJson(item);
      if (known && known.payload !== payload) fail('m4_cross_phase_identity_streaming_event_drift');
    }
    const novelEntries = (knownSession ? 0 : 1) + safeBlock.events.filter(item => !getEvent.get(item.legacyEventId)).length;
    if (current.sessions + current.events + novelEntries > M4_CROSS_PHASE_IDENTITY_MAX_TOTAL_ENTRIES) fail('m4_cross_phase_identity_streaming_bounds_exceeded');
    if (!knownSession) insertSession.run(safeBlock.session.legacySessionId, bucketFor(safeBlock.session.legacySessionId, 'ses_'), sessionPayload);
    for (const item of safeBlock.events) {
      if (!getEvent.get(item.legacyEventId)) {
        insertEvent.run(item.legacyEventId, bucketFor(item.legacyEventId, 'evt_'), item.legacySessionId, item.conversationId, item.sourceInstanceId, canonicalJson(item));
        for (const reference of [item.replacesLegacyEventId, item.tombstonesLegacyEventId, ...item.conflictsWithLegacyEventIds].filter(Boolean)) insertReference.run(item.legacyEventId, reference);
      }
    }
    insertBlock.run(blockDigest); incrementAccepted.run();
    return { blockDigest, accepted: true };
  });
  function accept(input) {
    try { assertOpen(); if (sealing || sealed || getMeta.get('seal_binding')) fail('m4_cross_phase_identity_streaming_sealed'); return Object.freeze(writeBlock(block(input))); }
    catch (error) { if (typeof error?.code === 'string' && error.code.startsWith('m4_cross_phase_identity_')) throw error; fail('m4_cross_phase_identity_streaming_state_invalid'); }
  }
  function validateStoredReferences() {
    const invalidSession = db.prepare(`SELECT 1 FROM m4_stream_events e LEFT JOIN m4_stream_sessions s ON s.legacy_session_id=e.legacy_session_id WHERE s.legacy_session_id IS NULL LIMIT 1`).get();
    if (invalidSession) fail('m4_cross_phase_identity_streaming_session_binding_invalid');
    const invalidReference = db.prepare(`SELECT 1 FROM m4_stream_references r JOIN m4_stream_events e ON e.legacy_event_id=r.legacy_event_id LEFT JOIN m4_stream_events t ON t.legacy_event_id=r.target_legacy_event_id WHERE t.legacy_event_id IS NULL OR t.legacy_session_id<>e.legacy_session_id OR t.conversation_id<>e.conversation_id OR t.source_instance_id<>e.source_instance_id LIMIT 1`).get();
    if (invalidReference) fail('m4_cross_phase_identity_streaming_reference_invalid');
  }
  async function seal({ traversalCompletion, completionKeyDocument } = {}) {
    assertOpen(); if (sealing) fail('m4_cross_phase_identity_streaming_sealed');
    const safeCompletionKeyDocument = clone(completionKeyDocument, 'm4_cross_phase_identity_streaming_completion_key_invalid');
    const completion = verifyM4CrossPhaseIdentityTraversalCompletion(traversalCompletion, safeCompletionKeyDocument); const completionDigest = digest(completion);
    const coveredThrough = completion.coveredThrough; const backfillBinding = completion.archiveBinding;
    const requestedBinding = canonicalJson({ coveredThrough, backfillBinding, completionDigest });
    if (sealed) {
      if (requestedBinding !== sealedBinding || completionDigest !== sealCompletionDigest) fail('m4_cross_phase_identity_streaming_seal_binding_invalid');
      try { return structuredClone(JSON.parse(sealedResult)); } catch { fail('m4_cross_phase_identity_streaming_state_invalid'); }
    }
    const completionMaterial = completionKeyMaterial(safeCompletionKeyDocument);
    try { const left = Buffer.alloc(64); const right = Buffer.alloc(64); try { secret.copy(left); completionMaterial.copy(right); if (crypto.timingSafeEqual(left,right)) fail('m4_cross_phase_identity_streaming_completion_key_separation_invalid'); } finally { left.fill(0); right.fill(0); } } finally { completionMaterial.fill(0); }
    const actualCommitment = registryCommitment(secret, registryKeyId);
    if (completion.registryKeyId !== registryKeyId || !safeEqual(completion.registryKeyCommitment, actualCommitment)) fail('m4_cross_phase_identity_streaming_completion_registry_binding_invalid');
    // Validate the fixed authority inputs before recording an irreversible
    // seal intent; page descriptors are supplied only after bounded streaming.
    createM4CrossPhaseIdentityAuthority({ coveredThrough, backfillBinding, pageDescriptors: [] }, secret);
    try { const persisted = persistSealIntent(requestedBinding, completionDigest, completion.coverage); sealedBinding = persisted.binding; sealCompletionDigest = persisted.completionDigest; }
    catch (error) { if (typeof error?.code === 'string' && error.code.startsWith('m4_cross_phase_identity_')) throw error; fail('m4_cross_phase_identity_streaming_state_invalid'); }
    sealing = true;
    try {
      validateStoredReferences(); const descriptors = [];
      for (const [entryKind, table, id, prefix] of [['event', 'm4_stream_events', 'legacy_event_id', 'evt_'], ['session', 'm4_stream_sessions', 'legacy_session_id', 'ses_']]) {
        for (let bucketIndex = 0; bucketIndex < 256; bucketIndex += 1) {
          let after = null; let shard = 0;
          while (true) {
            const range = bucketRange(prefix, bucketIndex, after); const bucket = range.bucket;
            assertOpen(); const rows = db.prepare(`SELECT ${id} AS id,payload FROM ${table} WHERE ${id}>? AND ${id}<? ORDER BY ${id} LIMIT ?`).all(range.lower, range.upper, M4_CROSS_PHASE_IDENTITY_MAX_PAGE_ENTRIES);
            if (!rows.length) break;
            const entries = rows.map(row => { try { return JSON.parse(row.payload); } catch { fail('m4_cross_phase_identity_streaming_state_invalid'); } });
            const page = pageLimit(entries, bucket, entryKind, shard); const count = page.events.length + page.sessions.length;
            if (descriptors.length >= M4_CROSS_PHASE_IDENTITY_MAX_AUTHORITY_PAGES) fail('m4_cross_phase_identity_streaming_page_bounds_exceeded');
            let acknowledgement;
            try { acknowledgement = await writePage(structuredClone(page)); }
            catch { fail('m4_cross_phase_identity_streaming_page_write_failed'); }
            pageAck(acknowledgement, page);
            descriptors.push(describeM4CrossPhaseIdentityPage(page));
            after = rows[count - 1].id; shard += 1;
          }
        }
      }
      descriptors.sort((left, right) => left.pageKey.localeCompare(right.pageKey));
      const authority = createM4CrossPhaseIdentityAuthority({ coveredThrough, backfillBinding, pageDescriptors: descriptors }, secret);
      const coverage = { acceptedBlockCount: Number(acceptedCount.get().value), sessionCount: authority.coverage.sessionCount, eventCount: authority.coverage.eventCount, pageCount: descriptors.length };
      const result = { authority, coverage }; setMeta.run('sealed_result', canonicalJson(result));
      sealedResult = canonicalJson(result); sealed = true; secret.fill(0); secret = null;
      return structuredClone(result);
    } catch (error) {
      if (typeof error?.code === 'string' && error.code.startsWith('m4_cross_phase_identity_')) throw error;
      fail('m4_cross_phase_identity_streaming_state_invalid');
    } finally { sealing = false; }
  }
  function close() { if (closed) return; closed = true; try { if (secret) secret.fill(0); secret = null; db.close(); fs.closeSync(parent.fd); } catch { fail('m4_cross_phase_identity_streaming_close_failed'); } }
  return Object.freeze({ kind: 'm4-cross-phase-identity-streaming-writer/v1', accept, seal, close });
}
