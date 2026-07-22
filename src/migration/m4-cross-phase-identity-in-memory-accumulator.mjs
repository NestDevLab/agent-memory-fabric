import crypto from 'node:crypto';

import {
  createM4CrossPhaseIdentityRegistry,
} from './m4-cross-phase-identity-registry.mjs';
import {
  deriveM4V3ConversationIdFromLegacySessionId,
  deriveM4V3EventIdFromLegacyEventId,
  deriveM4V3SourceInstanceIdFromLegacySession,
} from './m4-v2-conversation-projector.mjs';
import { canonicalJson } from '../ingest/transcripts/canonical.mjs';
import { normalizeContextTags, normalizeSessionContextBinding, sessionContextBinding } from '../ingest/raw-projection-v2.mjs';

export const M4_CROSS_PHASE_PROJECTOR_IDENTITY_BLOCK_SCHEMA = 'amf.m4-cross-phase-projector-identity-block/v1';
export const M4_CROSS_PHASE_IDENTITY_IN_MEMORY_ACCUMULATOR_COMPLETION_SCHEMA = 'amf.m4-cross-phase-identity-in-memory-accumulator-completion/v1';
export const M4_CROSS_PHASE_IDENTITY_IN_MEMORY_ACCUMULATOR_MAX_TOTAL_ENTRIES = 20_000;

const SESSION_ID = /^ses_[a-f0-9]{64}$/;
const EVENT_ID = /^evt_[a-f0-9]{64}$/;
const CONVERSATION_ID = /^ccon_[a-z0-9][a-z0-9_-]{7,127}$/;
const SOURCE_INSTANCE_ID = /^src_[a-z0-9][a-z0-9_-]{7,127}$/;
const SOURCE_TAG = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}:[a-f0-9]{64}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const KINDS = new Set(['dm', 'group', 'channel', 'thread', 'session', 'unknown']);
const ROLES = new Set(['user', 'assistant']);
const DIRECTIONS = new Set(['inbound', 'outbound']);
const STATES = new Set(['active', 'edited', 'replacement', 'tombstone', 'conflict']);

function fail(code) { const error = new Error(code); error.code = code; throw error; }
function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function exact(value, keys) { return plain(value) && Object.keys(value).sort().join('\0') === [...keys].sort().join('\0'); }
function digest(value) { return `sha256:${crypto.createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`; }
function completionDigest(value) { return digest(['amf.m4-cross-phase-identity-in-memory-accumulator-completion/v1/digest', value]); }
function clone(value, code) { try { return structuredClone(value); } catch { fail(code); } }

function tags(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 64
    || value.some(item => typeof item !== 'string' || !SOURCE_TAG.test(item))) fail('m4_cross_phase_identity_in_memory_accumulator_block_invalid');
  const result = [...value];
  for (let index = 1; index < result.length; index += 1) if (result[index - 1] >= result[index]) fail('m4_cross_phase_identity_in_memory_accumulator_block_invalid');
  return result;
}
function session(value) {
  if (!exact(value, ['legacySessionId', 'conversationId', 'conversationKind', 'sessionContextTags'])
    || !SESSION_ID.test(value.legacySessionId) || !CONVERSATION_ID.test(value.conversationId) || !KINDS.has(value.conversationKind)) {
    fail('m4_cross_phase_identity_in_memory_accumulator_block_invalid');
  }
  let sessionContextTags;
  try { sessionContextTags = normalizeSessionContextBinding(value.sessionContextTags); }
  catch { fail('m4_cross_phase_identity_in_memory_accumulator_block_invalid'); }
  if (deriveM4V3ConversationIdFromLegacySessionId(value.legacySessionId) !== value.conversationId) fail('m4_cross_phase_identity_in_memory_accumulator_binding_invalid');
  return { legacySessionId: value.legacySessionId, conversationId: value.conversationId,
    conversationKind: value.conversationKind, sessionContextTags };
}
function event(value, knownSessions) {
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
    || value.conflictsWithLegacyEventIds.some(item => typeof item !== 'string' || !EVENT_ID.test(item))) fail('m4_cross_phase_identity_in_memory_accumulator_block_invalid');
  if (new Set(value.conflictsWithLegacyEventIds).size !== value.conflictsWithLegacyEventIds.length
    || value.conflictsWithLegacyEventIds.some((item, index) => index && value.conflictsWithLegacyEventIds[index - 1] >= item)
    || (value.state === 'active' && (value.revision !== 1 || value.replacesLegacyEventId !== null || value.tombstonesLegacyEventId !== null || value.conflictsWithLegacyEventIds.length))
    || (['edited', 'replacement'].includes(value.state) && (value.revision < 2 || value.replacesLegacyEventId === null || value.tombstonesLegacyEventId !== null || value.conflictsWithLegacyEventIds.length))
    || (value.state === 'tombstone' && (value.replacesLegacyEventId !== null || value.tombstonesLegacyEventId === null || value.conflictsWithLegacyEventIds.length))
    || (value.state === 'conflict' && (value.replacesLegacyEventId !== null || value.tombstonesLegacyEventId !== null || value.conflictsWithLegacyEventIds.length < 1))) fail('m4_cross_phase_identity_in_memory_accumulator_block_invalid');
  const sourceTags = tags(value.sourceTags);
  let authorizationContextTags;
  try { authorizationContextTags = normalizeContextTags(value.authorizationContextTags); }
  catch { fail('m4_cross_phase_identity_in_memory_accumulator_block_invalid'); }
  const owner = knownSessions.get(value.legacySessionId);
  let eventSessionContextTags;
  try { eventSessionContextTags = sessionContextBinding(authorizationContextTags); }
  catch { fail('m4_cross_phase_identity_in_memory_accumulator_block_invalid'); }
  if (!owner || owner.conversationId !== value.conversationId || owner.conversationKind !== value.conversationKind
    || canonicalJson(owner.sessionContextTags) !== canonicalJson(eventSessionContextTags)
    || deriveM4V3EventIdFromLegacyEventId(value.legacyEventId) !== value.eventId
    || deriveM4V3ConversationIdFromLegacySessionId(value.legacySessionId) !== value.conversationId
    || deriveM4V3SourceInstanceIdFromLegacySession(value.legacySessionId, sourceTags) !== value.sourceInstanceId) {
    fail('m4_cross_phase_identity_in_memory_accumulator_binding_invalid');
  }
  return { legacyEventId: value.legacyEventId, legacySessionId: value.legacySessionId, eventId: value.eventId,
    conversationId: value.conversationId, sourceInstanceId: value.sourceInstanceId, sourceTags,
    conversationKind: value.conversationKind, authorizationContextTags, role: value.role, direction: value.direction,
    state: value.state, revision: value.revision, replacesLegacyEventId: value.replacesLegacyEventId,
    tombstonesLegacyEventId: value.tombstonesLegacyEventId, conflictsWithLegacyEventIds: [...value.conflictsWithLegacyEventIds] };
}
function block(value) {
  const safe = clone(value, 'm4_cross_phase_identity_in_memory_accumulator_block_invalid');
  if (!exact(safe, ['schema', 'session', 'events']) || safe.schema !== M4_CROSS_PHASE_PROJECTOR_IDENTITY_BLOCK_SCHEMA
    || !Array.isArray(safe.events) || safe.events.length < 1 || safe.events.length > 34) fail('m4_cross_phase_identity_in_memory_accumulator_block_invalid');
  const safeSession = session(safe.session); const sessions = new Map([[safeSession.legacySessionId, safeSession]]);
  const events = safe.events.map(item => event(item, sessions)).sort((left, right) => left.legacyEventId.localeCompare(right.legacyEventId));
  if (new Set(events.map(item => item.legacyEventId)).size !== events.length) fail('m4_cross_phase_identity_in_memory_accumulator_block_invalid');
  const byId = new Map(events.map(item => [item.legacyEventId, item]));
  for (const item of events) for (const reference of [item.replacesLegacyEventId, item.tombstonesLegacyEventId, ...item.conflictsWithLegacyEventIds].filter(Boolean)) {
    const target = byId.get(reference);
    if (!target || target.legacySessionId !== item.legacySessionId || target.conversationId !== item.conversationId
      || target.sourceInstanceId !== item.sourceInstanceId) fail('m4_cross_phase_identity_in_memory_accumulator_reference_invalid');
  }
  return { schema: safe.schema, session: safeSession, events };
}
function backfillBinding(value) {
  if (!exact(value, ['completionDigest', 'catalogRevisionDigest']) || !DIGEST.test(value.completionDigest) || !DIGEST.test(value.catalogRevisionDigest)) fail('m4_cross_phase_identity_in_memory_accumulator_seal_invalid');
  return { completionDigest: value.completionDigest, catalogRevisionDigest: value.catalogRevisionDigest };
}
function scanCompletion(value) {
  if (!exact(value, ['complete', 'acceptedGroupCount', 'excludedGroupCount', 'traversalDigest']) || value.complete !== true
    || !Number.isSafeInteger(value.acceptedGroupCount) || value.acceptedGroupCount < 0
    || !Number.isSafeInteger(value.excludedGroupCount) || value.excludedGroupCount < 0 || !DIGEST.test(value.traversalDigest)) {
    fail('m4_cross_phase_identity_in_memory_accumulator_scan_incomplete');
  }
  return { complete: true, acceptedGroupCount: value.acceptedGroupCount, excludedGroupCount: value.excludedGroupCount, traversalDigest: value.traversalDigest };
}
function coveredThrough(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(value)) fail('m4_cross_phase_identity_in_memory_accumulator_seal_invalid');
  return value;
}

// This bounded helper accepts the projector callback's content-free shape for
// small fixtures and tests. It is not a production traversal or deployment
// path, and its unsigned completion never establishes callback provenance.
// A later streaming writer may reuse the logical shape only after its own
// trusted traversal and signed completion design are implemented.
export function createM4CrossPhaseIdentityInMemoryAccumulator({ registrySecret, maxEntries = M4_CROSS_PHASE_IDENTITY_IN_MEMORY_ACCUMULATOR_MAX_TOTAL_ENTRIES } = {}) {
  if (!Buffer.isBuffer(registrySecret) || registrySecret.length !== 32 || !Number.isSafeInteger(maxEntries)
    || maxEntries < 1 || maxEntries > M4_CROSS_PHASE_IDENTITY_IN_MEMORY_ACCUMULATOR_MAX_TOTAL_ENTRIES) fail('m4_cross_phase_identity_in_memory_accumulator_request_invalid');
  const secret = Buffer.from(registrySecret);
  const sessions = new Map(); const events = new Map(); let acceptedBlocks = 0; let sealed = false;
  function retain(map, id, value, driftCode) {
    const prior = map.get(id);
    if (prior === undefined) { map.set(id, value); return true; }
    if (canonicalJson(prior) !== canonicalJson(value)) fail(driftCode);
    return false;
  }
  function accept(value) {
    if (sealed) fail('m4_cross_phase_identity_in_memory_accumulator_sealed');
    const safe = block(value); const blockDigest = digest(safe);
    const priorSession = sessions.get(safe.session.legacySessionId);
    if (priorSession !== undefined && canonicalJson(priorSession) !== canonicalJson(safe.session)) fail('m4_cross_phase_identity_in_memory_accumulator_session_drift');
    const novelEvents = safe.events.filter(item => {
      const prior = events.get(item.legacyEventId);
      if (prior === undefined) return true;
      if (canonicalJson(prior) !== canonicalJson(item)) fail('m4_cross_phase_identity_in_memory_accumulator_event_drift');
      return false;
    });
    if (sessions.size + (priorSession === undefined ? 1 : 0) + events.size + novelEvents.length > maxEntries) fail('m4_cross_phase_identity_in_memory_accumulator_bounds_exceeded');
    retain(sessions, safe.session.legacySessionId, safe.session, 'm4_cross_phase_identity_in_memory_accumulator_session_drift');
    for (const item of safe.events) retain(events, item.legacyEventId, item, 'm4_cross_phase_identity_in_memory_accumulator_event_drift');
    if (novelEvents.length || priorSession === undefined) acceptedBlocks += 1;
    return Object.freeze({ blockDigest, accepted: novelEvents.length > 0 || priorSession === undefined });
  }
  function seal({ coveredThrough: cutoff, backfillBinding: inputBinding, scanCompletion: inputCompletion } = {}) {
    if (sealed) fail('m4_cross_phase_identity_in_memory_accumulator_sealed');
    const safeCompletion = scanCompletion(inputCompletion);
    if (safeCompletion.acceptedGroupCount !== acceptedBlocks) fail('m4_cross_phase_identity_in_memory_accumulator_scan_mismatch');
    const binding = backfillBinding(inputBinding); const safeCutoff = coveredThrough(cutoff);
    const safeSessions = [...sessions.values()].sort((left, right) => left.legacySessionId.localeCompare(right.legacySessionId));
    const safeEvents = [...events.values()].sort((left, right) => left.legacyEventId.localeCompare(right.legacyEventId));
    const registry = createM4CrossPhaseIdentityRegistry({ coveredThrough: safeCutoff, backfillBinding: binding,
      sessions: safeSessions, events: safeEvents }, secret);
    const completion = { schema: M4_CROSS_PHASE_IDENTITY_IN_MEMORY_ACCUMULATOR_COMPLETION_SCHEMA, version: 1,
      coveredThrough: safeCutoff, registryAuthorityDigest: digest(registry.authority), backfillBinding: binding, scanCompletion: safeCompletion,
      coverage: { acceptedGroupCount: acceptedBlocks, excludedGroupCount: safeCompletion.excludedGroupCount,
        sessionCount: safeSessions.length, eventCount: safeEvents.length,
        pageDigest: registry.authority.coverage.pageDigest, pages: registry.authority.pages },
      digest: null };
    completion.digest = completionDigest({ ...completion, digest: null });
    sealed = true;
    return structuredClone({ registry, completion });
  }
  return Object.freeze({ kind: 'm4-cross-phase-projector-identity-in-memory-accumulator/v1', accept, seal });
}
