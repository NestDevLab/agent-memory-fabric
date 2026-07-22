import crypto from 'node:crypto';

import { isConversationEventUtcTimestamp } from '../conversation-event-v3.mjs';
import {
  normalizeContextTags,
  normalizeSessionContextBinding,
  sessionContextBinding,
  validateProjectionV2,
} from '../ingest/raw-projection-v2.mjs';
import { canonicalJson } from '../ingest/transcripts/canonical.mjs';
import {
  deriveM4V3ConversationIdFromLegacySessionId,
  deriveM4V3EventIdFromLegacyEventId,
  deriveM4V3SourceInstanceIdFromLegacySession,
} from './m4-v2-conversation-projector.mjs';

export const M4_CROSS_PHASE_IDENTITY_AUTHORITY_SCHEMA = 'amf.m4-cross-phase-identity-authority/v1';
export const M4_CROSS_PHASE_IDENTITY_PAGE_SCHEMA = 'amf.m4-cross-phase-identity-page/v1';
export const M4_CROSS_PHASE_IDENTITY_MAX_PAGE_ENTRIES = 10_000;
export const M4_CROSS_PHASE_IDENTITY_MAX_TOTAL_ENTRIES = 2_000_000;

const SESSION_ID = /^ses_[a-f0-9]{64}$/;
const EVENT_ID = /^evt_[a-f0-9]{64}$/;
const CONVERSATION_ID = /^ccon_[a-z0-9][a-z0-9_-]{7,127}$/;
const SOURCE_INSTANCE_ID = /^src_[a-z0-9][a-z0-9_-]{7,127}$/;
const SOURCE_TAG = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}:[a-f0-9]{64}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const MAC = /^hmac-sha256:[A-Za-z0-9_-]{43}$/;
const BUCKET = /^[a-f0-9]{2}$/;
const PAGE_KEY = /^[a-f0-9]{2}-[es]-[0-9]{4}$/;
const CONVERSATION_KINDS = new Set(['dm', 'group', 'channel', 'thread', 'session', 'unknown']);
const ROLES = new Set(['user', 'assistant']);
const DIRECTIONS = new Set(['inbound', 'outbound']);
const STATES = new Set(['active', 'edited', 'replacement', 'tombstone', 'conflict']);
const NATIVE_SOURCES = new Set(['codex', 'claude', 'hermes', 'openclaw']);
const MAX_PAGE_BYTES = 32 * 1024 * 1024;
const MAX_AUTHORITY_PAGES = 768;
const MAX_CACHE_PAGES = 256;

function fail(code) { const error = new Error(code); error.code = code; throw error; }
function exact(value, keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype
    && Object.keys(value).sort().join('\0') === [...keys].sort().join('\0');
}
function key(value) {
  if (!Buffer.isBuffer(value) || value.length !== 32) fail('m4_cross_phase_identity_key_invalid');
  return value;
}
function digest(value) {
  return `sha256:${crypto.createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`;
}
function mac(value, secret) {
  return `hmac-sha256:${crypto.createHmac('sha256', secret).update(canonicalJson(value), 'utf8').digest('base64url')}`;
}
function safeEqual(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') return false;
  const actual = Buffer.from(left, 'utf8'); const expected = Buffer.from(right, 'utf8');
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}
function timestamp(value, code) {
  if (typeof value !== 'string' || !isConversationEventUtcTimestamp(value) || !value.endsWith('Z')) fail(code);
  return value;
}
function timestampKey(value) {
  const match = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?Z$/.exec(value);
  if (!match) fail('m4_cross_phase_identity_timestamp_invalid');
  return `${match[1]}.${(match[2] || '').padEnd(9, '0')}`;
}
function bucketFor(value, prefix) { return value.slice(prefix.length, prefix.length + 2); }
function sortedSourceTags(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 64
    || value.some(item => typeof item !== 'string' || !SOURCE_TAG.test(item))) fail('m4_cross_phase_identity_entry_invalid');
  const result = [...value];
  for (let index = 1; index < result.length; index += 1) {
    if (result[index - 1] >= result[index]) fail('m4_cross_phase_identity_entry_invalid');
  }
  return result;
}
function sessionEntry(value) {
  if (!exact(value, ['legacySessionId', 'conversationId', 'conversationKind', 'sessionContextTags'])
    || !SESSION_ID.test(value.legacySessionId) || !CONVERSATION_ID.test(value.conversationId)
    || !CONVERSATION_KINDS.has(value.conversationKind)) fail('m4_cross_phase_identity_entry_invalid');
  let context;
  try { context = normalizeSessionContextBinding(value.sessionContextTags); }
  catch { fail('m4_cross_phase_identity_entry_invalid'); }
  if (deriveM4V3ConversationIdFromLegacySessionId(value.legacySessionId) !== value.conversationId) {
    fail('m4_cross_phase_identity_binding_invalid');
  }
  return { legacySessionId: value.legacySessionId, conversationId: value.conversationId,
    conversationKind: value.conversationKind, sessionContextTags: context };
}
function eventEntry(value) {
  if (!exact(value, ['legacyEventId', 'legacySessionId', 'eventId', 'conversationId', 'sourceInstanceId',
    'sourceTags', 'conversationKind', 'authorizationContextTags', 'role', 'direction', 'state', 'revision',
    'replacesLegacyEventId', 'tombstonesLegacyEventId', 'conflictsWithLegacyEventIds'])
    || !EVENT_ID.test(value.legacyEventId) || !SESSION_ID.test(value.legacySessionId)
    || !CONVERSATION_ID.test(value.conversationId) || !SOURCE_INSTANCE_ID.test(value.sourceInstanceId)
    || !CONVERSATION_KINDS.has(value.conversationKind) || !ROLES.has(value.role) || !DIRECTIONS.has(value.direction)
    || !STATES.has(value.state) || !Number.isSafeInteger(value.revision) || value.revision < 1
    || !(value.replacesLegacyEventId === null || EVENT_ID.test(value.replacesLegacyEventId))
    || !(value.tombstonesLegacyEventId === null || EVENT_ID.test(value.tombstonesLegacyEventId))
    || !Array.isArray(value.conflictsWithLegacyEventIds) || value.conflictsWithLegacyEventIds.length > 32
    || value.conflictsWithLegacyEventIds.some(item => typeof item !== 'string' || !EVENT_ID.test(item))) {
    fail('m4_cross_phase_identity_entry_invalid');
  }
  if (new Set(value.conflictsWithLegacyEventIds).size !== value.conflictsWithLegacyEventIds.length
    || value.conflictsWithLegacyEventIds.some((item, index) => index > 0 && value.conflictsWithLegacyEventIds[index - 1] >= item)
    || (value.state === 'active' && (value.revision !== 1 || value.replacesLegacyEventId !== null
      || value.tombstonesLegacyEventId !== null || value.conflictsWithLegacyEventIds.length))
    || (['edited', 'replacement'].includes(value.state) && (value.revision < 2 || value.replacesLegacyEventId === null
      || value.tombstonesLegacyEventId !== null || value.conflictsWithLegacyEventIds.length))
    || (value.state === 'tombstone' && (value.tombstonesLegacyEventId === null || value.replacesLegacyEventId !== null
      || value.conflictsWithLegacyEventIds.length))
    || (value.state === 'conflict' && (value.conflictsWithLegacyEventIds.length < 1 || value.replacesLegacyEventId !== null
      || value.tombstonesLegacyEventId !== null))) fail('m4_cross_phase_identity_entry_invalid');
  let context;
  try { context = normalizeContextTags(value.authorizationContextTags); }
  catch { fail('m4_cross_phase_identity_entry_invalid'); }
  const tags = sortedSourceTags(value.sourceTags);
  if (deriveM4V3EventIdFromLegacyEventId(value.legacyEventId) !== value.eventId
    || deriveM4V3ConversationIdFromLegacySessionId(value.legacySessionId) !== value.conversationId
    || deriveM4V3SourceInstanceIdFromLegacySession(value.legacySessionId, tags) !== value.sourceInstanceId) {
    fail('m4_cross_phase_identity_binding_invalid');
  }
  return { legacyEventId: value.legacyEventId, legacySessionId: value.legacySessionId,
    eventId: value.eventId, conversationId: value.conversationId, sourceInstanceId: value.sourceInstanceId,
    sourceTags: tags, conversationKind: value.conversationKind, authorizationContextTags: context,
    role: value.role, direction: value.direction, state: value.state, revision: value.revision,
    replacesLegacyEventId: value.replacesLegacyEventId, tombstonesLegacyEventId: value.tombstonesLegacyEventId,
    conflictsWithLegacyEventIds: [...value.conflictsWithLegacyEventIds] };
}
function validateEventReferences(events) {
  const byId = new Map(events.map(item => [item.legacyEventId, item]));
  for (const item of events) {
    const references = [item.replacesLegacyEventId, item.tombstonesLegacyEventId,
      ...item.conflictsWithLegacyEventIds].filter(Boolean);
    for (const reference of references) {
      const target = byId.get(reference);
      if (!target || target.conversationId !== item.conversationId
        || target.legacySessionId !== item.legacySessionId
        || target.sourceInstanceId !== item.sourceInstanceId) fail('m4_cross_phase_identity_reference_invalid');
    }
  }
}
function validateEventSessionBindings(sessions, events) {
  const byId = new Map(sessions.map(item => [item.legacySessionId, item]));
  for (const item of events) {
    const session = byId.get(item.legacySessionId);
    let eventSessionContext;
    try { eventSessionContext = sessionContextBinding(item.authorizationContextTags); }
    catch { fail('m4_cross_phase_identity_session_binding_invalid'); }
    if (!session || session.conversationId !== item.conversationId
      || session.conversationKind !== item.conversationKind
      || canonicalJson(session.sessionContextTags) !== canonicalJson(eventSessionContext)) {
      fail('m4_cross_phase_identity_session_binding_invalid');
    }
  }
}
function sortedEntries(value, normalize, id, code, maxEntries = M4_CROSS_PHASE_IDENTITY_MAX_PAGE_ENTRIES) {
  if (!Array.isArray(value) || value.length > maxEntries) fail(code);
  const result = value.map(normalize);
  for (let index = 1; index < result.length; index += 1) if (result[index - 1][id] >= result[index][id]) fail(code);
  return result;
}
function pageBody(pageKey, bucket, entryKind, shard, sessions, events) {
  return { schema: M4_CROSS_PHASE_IDENTITY_PAGE_SCHEMA, version: 1,
    pageKey, bucket, entryKind, shard, sessions, events };
}
function createPage(bucket, entryKind, shard, entries) {
  if (!BUCKET.test(bucket) || !['event', 'session'].includes(entryKind)
    || !Number.isSafeInteger(shard) || shard < 0 || shard > 9_999) fail('m4_cross_phase_identity_page_invalid');
  const marker = entryKind === 'event' ? 'e' : 's';
  const pageKey = `${bucket}-${marker}-${String(shard).padStart(4, '0')}`;
  const safeSessions = entryKind === 'session'
    ? sortedEntries(entries, sessionEntry, 'legacySessionId', 'm4_cross_phase_identity_page_invalid') : [];
  const safeEvents = entryKind === 'event'
    ? sortedEntries(entries, eventEntry, 'legacyEventId', 'm4_cross_phase_identity_page_invalid') : [];
  if ((entryKind === 'session' && safeSessions.some(item => bucketFor(item.legacySessionId, 'ses_') !== bucket))
    || (entryKind === 'event' && safeEvents.some(item => bucketFor(item.legacyEventId, 'evt_') !== bucket))) {
    fail('m4_cross_phase_identity_page_invalid');
  }
  const body = pageBody(pageKey, bucket, entryKind, shard, safeSessions, safeEvents);
  const result = { ...body, digest: digest(body) };
  if (Buffer.byteLength(canonicalJson(result), 'utf8') > MAX_PAGE_BYTES) {
    fail('m4_cross_phase_identity_page_byte_limit');
  }
  return result;
}
function verifyPage(value, descriptor) {
  if (!exact(value, ['schema', 'version', 'pageKey', 'bucket', 'entryKind', 'shard', 'sessions', 'events', 'digest'])
    || !DIGEST.test(value.digest)) {
    fail('m4_cross_phase_identity_page_invalid');
  }
  const entries = value.entryKind === 'event' ? value.events : value.sessions;
  let page;
  try { page = createPage(value.bucket, value.entryKind, value.shard, entries); }
  catch { fail('m4_cross_phase_identity_page_invalid'); }
  if (page.digest !== value.digest || canonicalJson(descriptor) !== canonicalJson(descriptorForPage(page))) {
    fail('m4_cross_phase_identity_page_invalid');
  }
  return page;
}
function descriptorForPage(page) {
  const entries = page.entryKind === 'event' ? page.events : page.sessions;
  const id = page.entryKind === 'event' ? 'legacyEventId' : 'legacySessionId';
  return { pageKey: page.pageKey, bucket: page.bucket, entryKind: page.entryKind, shard: page.shard,
    firstId: entries[0][id], lastId: entries.at(-1)[id], sessionCount: page.sessions.length,
    eventCount: page.events.length, digest: page.digest };
}
function descriptor(value) {
  if (!exact(value, ['pageKey', 'bucket', 'entryKind', 'shard', 'firstId', 'lastId',
    'sessionCount', 'eventCount', 'digest']) || !PAGE_KEY.test(value.pageKey) || !BUCKET.test(value.bucket)
    || !['event', 'session'].includes(value.entryKind) || !Number.isSafeInteger(value.shard)
    || value.shard < 0 || value.shard > 9_999
    || !Number.isSafeInteger(value.sessionCount) || value.sessionCount < 0
    || !Number.isSafeInteger(value.eventCount) || value.eventCount < 0 || !DIGEST.test(value.digest)
    || value.sessionCount + value.eventCount < 1 || value.sessionCount + value.eventCount > M4_CROSS_PHASE_IDENTITY_MAX_PAGE_ENTRIES
    || value.pageKey !== `${value.bucket}-${value.entryKind === 'event' ? 'e' : 's'}-${String(value.shard).padStart(4, '0')}`
    || (value.entryKind === 'event' && (value.sessionCount !== 0 || value.eventCount < 1
      || !EVENT_ID.test(value.firstId) || !EVENT_ID.test(value.lastId)))
    || (value.entryKind === 'session' && (value.eventCount !== 0 || value.sessionCount < 1
      || !SESSION_ID.test(value.firstId) || !SESSION_ID.test(value.lastId)))
    || value.firstId > value.lastId) {
    fail('m4_cross_phase_identity_authority_invalid');
  }
  return { pageKey: value.pageKey, bucket: value.bucket, entryKind: value.entryKind, shard: value.shard,
    firstId: value.firstId, lastId: value.lastId, sessionCount: value.sessionCount,
    eventCount: value.eventCount, digest: value.digest };
}
function descriptors(value) {
  if (!Array.isArray(value) || value.length > MAX_AUTHORITY_PAGES) fail('m4_cross_phase_identity_authority_invalid');
  const result = value.map(descriptor);
  for (let index = 1; index < result.length; index += 1) {
    if (result[index - 1].pageKey >= result[index].pageKey) fail('m4_cross_phase_identity_authority_invalid');
  }
  return result;
}
function backfillBinding(value) {
  if (!exact(value, ['completionDigest', 'catalogRevisionDigest'])
    || !DIGEST.test(value.completionDigest) || !DIGEST.test(value.catalogRevisionDigest)) {
    fail('m4_cross_phase_identity_authority_invalid');
  }
  return { completionDigest: value.completionDigest, catalogRevisionDigest: value.catalogRevisionDigest };
}
function authorityBody(coveredThrough, binding, pageDescriptors) {
  const sessionCount = pageDescriptors.reduce((sum, item) => sum + item.sessionCount, 0);
  const eventCount = pageDescriptors.reduce((sum, item) => sum + item.eventCount, 0);
  if (sessionCount + eventCount > M4_CROSS_PHASE_IDENTITY_MAX_TOTAL_ENTRIES) fail('m4_cross_phase_identity_authority_invalid');
  return { schema: M4_CROSS_PHASE_IDENTITY_AUTHORITY_SCHEMA, version: 1,
    coveredThrough: timestamp(coveredThrough, 'm4_cross_phase_identity_timestamp_invalid'),
    backfillBinding: backfillBinding(binding),
    coverage: { sessionCount, eventCount, pageDigest: digest(pageDescriptors) }, pages: pageDescriptors };
}
function partitionPages(values, entryKind, id, prefix) {
  const result = new Map();
  for (const value of values) {
    const bucket = bucketFor(value[id], prefix); const current = result.get(bucket) ?? [];
    current.push(value); result.set(bucket, current);
  }
  for (const current of result.values()) current.sort((left, right) => left[id].localeCompare(right[id]));
  const pages = [];
  for (const [bucket, current] of result.entries()) {
    for (let offset = 0, shard = 0; offset < current.length; shard += 1) {
      let lower = 1;
      let upper = Math.min(M4_CROSS_PHASE_IDENTITY_MAX_PAGE_ENTRIES, current.length - offset);
      let accepted = null;
      while (lower <= upper) {
        const size = Math.floor((lower + upper) / 2);
        try {
          accepted = createPage(bucket, entryKind, shard, current.slice(offset, offset + size));
          lower = size + 1;
        } catch (error) {
          if (error?.code !== 'm4_cross_phase_identity_page_byte_limit') throw error;
          upper = size - 1;
        }
      }
      if (accepted === null) fail('m4_cross_phase_identity_page_byte_limit');
      pages.push(accepted);
      offset += accepted.sessions.length + accepted.events.length;
    }
  }
  return pages;
}

export function createM4CrossPhaseIdentityRegistry({ coveredThrough, backfillBinding: binding, sessions = [], events = [] } = {}, secret) {
  const safeSessions = sortedEntries(sessions, sessionEntry, 'legacySessionId',
    'm4_cross_phase_identity_entries_invalid', M4_CROSS_PHASE_IDENTITY_MAX_TOTAL_ENTRIES);
  const safeEvents = sortedEntries(events, eventEntry, 'legacyEventId',
    'm4_cross_phase_identity_entries_invalid', M4_CROSS_PHASE_IDENTITY_MAX_TOTAL_ENTRIES);
  validateEventSessionBindings(safeSessions, safeEvents);
  validateEventReferences(safeEvents);
  if (safeSessions.length + safeEvents.length > M4_CROSS_PHASE_IDENTITY_MAX_TOTAL_ENTRIES) fail('m4_cross_phase_identity_entries_invalid');
  const pages = [...partitionPages(safeEvents, 'event', 'legacyEventId', 'evt_'),
    ...partitionPages(safeSessions, 'session', 'legacySessionId', 'ses_')]
    .sort((left, right) => left.pageKey.localeCompare(right.pageKey));
  const pageDescriptors = pages.map(descriptorForPage);
  const unsigned = authorityBody(coveredThrough, binding, pageDescriptors);
  return structuredClone({ authority: { ...unsigned, mac: mac(unsigned, key(secret)) }, pages });
}

export function verifyM4CrossPhaseIdentityAuthority(value, secret) {
  let snapshot;
  try { snapshot = structuredClone(value); } catch { fail('m4_cross_phase_identity_authority_invalid'); }
  if (!exact(snapshot, ['schema', 'version', 'coveredThrough', 'backfillBinding', 'coverage', 'pages', 'mac'])
    || snapshot.schema !== M4_CROSS_PHASE_IDENTITY_AUTHORITY_SCHEMA || snapshot.version !== 1
    || !exact(snapshot.coverage, ['sessionCount', 'eventCount', 'pageDigest'])
    || !Number.isSafeInteger(snapshot.coverage.sessionCount) || snapshot.coverage.sessionCount < 0
    || !Number.isSafeInteger(snapshot.coverage.eventCount) || snapshot.coverage.eventCount < 0
    || !DIGEST.test(snapshot.coverage.pageDigest) || !MAC.test(snapshot.mac)) fail('m4_cross_phase_identity_authority_invalid');
  const pageDescriptors = descriptors(snapshot.pages);
  const unsigned = authorityBody(snapshot.coveredThrough, snapshot.backfillBinding, pageDescriptors);
  if (canonicalJson(snapshot.coverage) !== canonicalJson(unsigned.coverage)
    || !safeEqual(snapshot.mac, mac(unsigned, key(secret)))) fail('m4_cross_phase_identity_authority_invalid');
  return structuredClone(unsigned);
}

function postCutoffBinding(value, expectedLegacyEventId, cutoff) {
  const hasTags = exact(value, ['legacyEventId', 'legacySessionId', 'eventId', 'conversationId',
    'sourceInstanceId', 'sourceTags', 'observedAt']);
  const hasTag = exact(value, ['legacyEventId', 'legacySessionId', 'eventId', 'conversationId',
    'sourceInstanceId', 'sourceTag', 'observedAt']);
  if (!(hasTags || hasTag)
    || value.legacyEventId !== expectedLegacyEventId || !EVENT_ID.test(value.legacyEventId)
    || !SESSION_ID.test(value.legacySessionId) || !CONVERSATION_ID.test(value.conversationId)
    || !SOURCE_INSTANCE_ID.test(value.sourceInstanceId)
    || deriveM4V3EventIdFromLegacyEventId(value.legacyEventId) !== value.eventId
    || deriveM4V3ConversationIdFromLegacySessionId(value.legacySessionId) !== value.conversationId
    || timestampKey(timestamp(value.observedAt, 'm4_cross_phase_identity_local_binding_invalid')) <= cutoff) {
    fail('m4_cross_phase_identity_local_binding_invalid');
  }
  let sourceTags;
  try { sourceTags = hasTags ? sortedSourceTags(value.sourceTags) : sortedSourceTags([value.sourceTag]); }
  catch { fail('m4_cross_phase_identity_local_binding_invalid'); }
  if (deriveM4V3SourceInstanceIdFromLegacySession(value.legacySessionId, sourceTags) !== value.sourceInstanceId) {
    fail('m4_cross_phase_identity_local_binding_invalid');
  }
  return { legacyEventId: value.legacyEventId, legacySessionId: value.legacySessionId, eventId: value.eventId,
    conversationId: value.conversationId, sourceInstanceId: value.sourceInstanceId, sourceTags,
    observedAt: value.observedAt };
}

export function createM4CrossPhaseIdentityResolver({ authority: input, loadPage, loadPostCutoffEvent = null } = {}, secret) {
  const authority = verifyM4CrossPhaseIdentityAuthority(input, secret);
  if (typeof loadPage !== 'function' || !(loadPostCutoffEvent === null || typeof loadPostCutoffEvent === 'function')) {
    fail('m4_cross_phase_identity_loader_invalid');
  }
  const descriptorsByPageKey = new Map(authority.pages.map(item => [item.pageKey, item]));
  const descriptorsByKindBucket = new Map();
  for (const item of authority.pages) {
    const keyValue = `${item.entryKind}:${item.bucket}`;
    const current = descriptorsByKindBucket.get(keyValue) ?? [];
    current.push(item); descriptorsByKindBucket.set(keyValue, current);
  }
  const cache = new Map(); const cutoff = timestampKey(authority.coveredThrough);
  function load(pageKey) {
    const descriptorValue = descriptorsByPageKey.get(pageKey);
    if (!descriptorValue) fail('m4_cross_phase_identity_page_unavailable');
    if (cache.has(pageKey)) {
      const page = cache.get(pageKey); cache.delete(pageKey); cache.set(pageKey, page); return page;
    }
    let value; try { value = loadPage(pageKey); } catch { fail('m4_cross_phase_identity_page_unavailable'); }
    if (value === null || value === undefined) fail('m4_cross_phase_identity_page_unavailable');
    const page = verifyPage(value, descriptorValue); cache.set(pageKey, page);
    if (cache.size > MAX_CACHE_PAGES) cache.delete(cache.keys().next().value);
    return page;
  }
  function find(entryKind, id, prefix) {
    const candidates = descriptorsByKindBucket.get(`${entryKind}:${bucketFor(id, prefix)}`) ?? [];
    const descriptorValue = candidates.find(item => item.firstId <= id && id <= item.lastId);
    if (!descriptorValue) return null;
    const entries = entryKind === 'event' ? load(descriptorValue.pageKey).events : load(descriptorValue.pageKey).sessions;
    const keyValue = entryKind === 'event' ? 'legacyEventId' : 'legacySessionId';
    return entries.find(item => item[keyValue] === id) ?? null;
  }
  function findSession(id) { return find('session', id, 'ses_'); }
  function findEvent(id) { return find('event', id, 'evt_'); }
  function resolveRegisteredReference(legacyEventId, registeredEvent) {
    if (legacyEventId === null) return null;
    const target = findEvent(legacyEventId);
    if (!target || target.legacySessionId !== registeredEvent.legacySessionId
      || target.conversationId !== registeredEvent.conversationId
      || target.sourceInstanceId !== registeredEvent.sourceInstanceId) {
      fail('m4_cross_phase_identity_reference_invalid');
    }
    return target.eventId;
  }
  function resolveBindingInternal({ legacyEventId, legacySessionId, sourceTags, conversationKind,
    authorizationContextTags, role, direction, effectiveTimestamp, priorLegacyEventId = null } = {},
  allowSourceTagMember = false) {
    if (!EVENT_ID.test(legacyEventId) || !SESSION_ID.test(legacySessionId)
      || !CONVERSATION_KINDS.has(conversationKind) || !ROLES.has(role) || !DIRECTIONS.has(direction)
      || !(priorLegacyEventId === null || (typeof priorLegacyEventId === 'string' && EVENT_ID.test(priorLegacyEventId)))) {
      fail('m4_cross_phase_identity_input_invalid');
    }
    let tags; let normalizedContext;
    try { tags = sortedSourceTags(sourceTags); normalizedContext = normalizeContextTags(authorizationContextTags); }
    catch { fail('m4_cross_phase_identity_input_invalid'); }
    let observed;
    try { observed = timestamp(effectiveTimestamp, 'm4_cross_phase_identity_input_invalid'); }
    catch { fail('m4_cross_phase_identity_input_invalid'); }
    const registeredSession = findSession(legacySessionId); const registeredEvent = findEvent(legacyEventId);
    let sessionBinding;
    try { sessionBinding = sessionContextBinding(normalizedContext); }
    catch { fail('m4_cross_phase_identity_input_invalid'); }
    if (registeredSession && (registeredSession.conversationKind !== conversationKind
      || canonicalJson(registeredSession.sessionContextTags) !== canonicalJson(sessionBinding))) {
      fail('m4_cross_phase_identity_binding_mismatch');
    }
    if (registeredEvent) {
      if (registeredEvent.legacySessionId !== legacySessionId
        || (allowSourceTagMember ? !tags.every(tag => registeredEvent.sourceTags.includes(tag))
          : canonicalJson(registeredEvent.sourceTags) !== canonicalJson(tags))
        || registeredEvent.conversationKind !== conversationKind || registeredEvent.role !== role
        || registeredEvent.direction !== direction
        || canonicalJson(registeredEvent.authorizationContextTags) !== canonicalJson(normalizedContext)) {
        fail('m4_cross_phase_identity_binding_mismatch');
      }
      return { legacyEventId, legacySessionId, eventId: registeredEvent.eventId,
        conversationId: registeredEvent.conversationId, sourceInstanceId: registeredEvent.sourceInstanceId,
        conversationKind, authorizationContextTags: normalizedContext, covered: true, state: registeredEvent.state,
        revision: registeredEvent.revision,
        replacesEventId: resolveRegisteredReference(registeredEvent.replacesLegacyEventId, registeredEvent),
        tombstonesEventId: resolveRegisteredReference(registeredEvent.tombstonesLegacyEventId, registeredEvent),
        conflictsWithEventIds: registeredEvent.conflictsWithLegacyEventIds.map(item => resolveRegisteredReference(item, registeredEvent)),
        priorEventId: null };
    }
    if (timestampKey(observed) <= cutoff) fail('m4_cross_phase_identity_registry_missing');
    let prior = null;
    if (priorLegacyEventId !== null) {
      prior = findEvent(priorLegacyEventId);
      if (prior === null) {
        if (loadPostCutoffEvent === null) fail('m4_cross_phase_identity_local_predecessor_missing');
        let localValue;
        try { localValue = loadPostCutoffEvent(priorLegacyEventId); } catch { fail('m4_cross_phase_identity_local_predecessor_missing'); }
        if (localValue === null || localValue === undefined) fail('m4_cross_phase_identity_local_predecessor_missing');
        prior = postCutoffBinding(localValue, priorLegacyEventId, cutoff);
      }
      const priorTags = prior.sourceTags;
      if (prior.legacySessionId !== legacySessionId || (allowSourceTagMember
        ? !tags.every(tag => priorTags.includes(tag)) : canonicalJson(priorTags) !== canonicalJson(tags))) {
        fail('m4_cross_phase_identity_binding_mismatch');
      }
    }
    const conversationId = registeredSession?.conversationId ?? deriveM4V3ConversationIdFromLegacySessionId(legacySessionId);
    const sourceInstanceId = prior?.sourceInstanceId ?? deriveM4V3SourceInstanceIdFromLegacySession(legacySessionId, tags);
    return { legacyEventId, legacySessionId, eventId: deriveM4V3EventIdFromLegacyEventId(legacyEventId), conversationId,
      sourceInstanceId, conversationKind, authorizationContextTags: normalizedContext, covered: false,
      state: null, revision: null, replacesEventId: null, tombstonesEventId: null, conflictsWithEventIds: [],
      priorEventId: priorLegacyEventId === null ? null : prior.eventId,
      postCutoffBinding: { legacyEventId, legacySessionId, eventId: deriveM4V3EventIdFromLegacyEventId(legacyEventId),
        conversationId, sourceInstanceId, ...(allowSourceTagMember ? { sourceTag: tags[0] } : { sourceTags: tags }),
        observedAt: observed } };
  }
  function publicBindingInput(value) {
    const required = ['legacyEventId', 'legacySessionId', 'sourceTags', 'conversationKind', 'authorizationContextTags',
      'role', 'direction', 'effectiveTimestamp'];
    const permitted = new Set([...required, 'priorLegacyEventId']);
    if (value === null || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype
      || required.some(item => !Object.hasOwn(value, item))
      || Object.keys(value).some(item => !permitted.has(item))) fail('m4_cross_phase_identity_input_invalid');
    return value;
  }
  return Object.freeze({
    kind: 'm4-cross-phase-identity-registry-v1', coveredThrough: authority.coveredThrough,
    coverageBinding: Object.freeze({ ...authority.coverage }),
    resolveBinding(input) { return resolveBindingInternal(publicBindingInput(input)); },
    resolve({ projection: inputProjection, sourceTag, priorLegacyEventId = null } = {}) {
      if (typeof sourceTag !== 'string' || !SOURCE_TAG.test(sourceTag)
        || !(priorLegacyEventId === null || (typeof priorLegacyEventId === 'string' && EVENT_ID.test(priorLegacyEventId)))) {
        fail('m4_cross_phase_identity_input_invalid');
      }
      let projection;
      try { projection = structuredClone(inputProjection); validateProjectionV2(projection); }
      catch { fail('m4_cross_phase_identity_input_invalid'); }
      if (projection.observationClass !== 'native' || !NATIVE_SOURCES.has(projection.sourceKind)
        || !EVENT_ID.test(projection.eventId) || !SESSION_ID.test(projection.sessionId)
        || !isConversationEventUtcTimestamp(projection.occurredAt)) fail('m4_cross_phase_identity_input_invalid');
      let sessionBinding; let authorizationContextTags;
      try { sessionBinding = sessionContextBinding(projection.contextTags); authorizationContextTags = normalizeContextTags(projection.contextTags); }
      catch { fail('m4_cross_phase_identity_input_invalid'); }
      return resolveBindingInternal({ legacyEventId: projection.eventId, legacySessionId: projection.sessionId,
        sourceTags: [sourceTag], conversationKind: projection.conversationKind, authorizationContextTags,
        role: projection.role, direction: projection.direction,
        effectiveTimestamp: projection.editedAt ?? projection.occurredAt, priorLegacyEventId }, true);
    },
  });
}
