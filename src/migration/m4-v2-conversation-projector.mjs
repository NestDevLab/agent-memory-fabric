import crypto from 'node:crypto';

import { compareConversationEvents, createConversationEvent } from '../conversation-event-v3.mjs';
import {
  compareObservations,
  sessionContextBinding,
  selectLogicalMessage,
  validateProjectionV2,
} from '../ingest/raw-projection-v2.mjs';
import { canonicalJson } from '../ingest/transcripts/canonical.mjs';

const SCHEMA = 'amf.m4-v2-conversation-projection/v1';
const LOGICAL_ID = /^lmsg_[a-f0-9]{64}$/;
const V2_EVENT_ID = /^evt_[a-f0-9]{64}$/;
const V2_SESSION_ID = /^ses_[a-f0-9]{64}$/;
const V3_TEXT_MAX = 65_536;
const SOURCE_TAG = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}:[a-f0-9]{64}$/;
const EXCLUSION_REASONS = new Set([
  'preferred_ineligible',
  'no_eligible_observations',
  'deletion_without_history',
]);

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function hasExactKeys(value, keys) {
  return isPlainObject(value)
    && Object.keys(value).length === keys.length
    && keys.every(key => Object.hasOwn(value, key));
}

function opaqueHash(domain, values) {
  return crypto.createHash('sha256').update(canonicalJson([domain, ...values]), 'utf8').digest('hex');
}

export function deriveM4V3ConversationIdFromLegacySessionId(sessionId) {
  if (typeof sessionId !== 'string' || !V2_SESSION_ID.test(sessionId)) fail('m4_v2_projector_legacy_session_id_invalid');
  return `ccon_${opaqueHash('amf.m4/v2-conversation-id/v1', [sessionId])}`;
}

function deriveConversationId(sessionId) { return deriveM4V3ConversationIdFromLegacySessionId(sessionId); }

export function deriveM4V3EventIdFromLegacyEventId(eventId) {
  if (typeof eventId !== 'string' || !V2_EVENT_ID.test(eventId)) fail('m4_v2_projector_legacy_event_id_invalid');
  return `cevt_${opaqueHash('amf.m4/v2-event-id/v1', [eventId])}`;
}

export function deriveM4V3SourceInstanceIdFromLegacySession(sessionId, sourceTags) {
  if (typeof sessionId !== 'string' || !V2_SESSION_ID.test(sessionId)
    || !Array.isArray(sourceTags) || sourceTags.length < 1 || sourceTags.length > 64
    || sourceTags.some(sourceTag => typeof sourceTag !== 'string' || !SOURCE_TAG.test(sourceTag))
    || new Set(sourceTags).size !== sourceTags.length
    || sourceTags.some((sourceTag, index) => index > 0 && sourceTags[index - 1] >= sourceTag)) {
    fail('m4_v2_projector_source_binding_invalid');
  }
  return `src_${opaqueHash('amf.m4/v2-source-instance/v1', [sessionId, sourceTags])}`;
}

function deriveSourceInstanceId(sessionId, sourceTags) {
  return deriveM4V3SourceInstanceIdFromLegacySession(sessionId, sourceTags);
}

function copyLogical(value) {
  const keys = [
    'logicalMessageId', 'preferredObservationId', 'payloadConflict',
    'tombstoned', 'selectionVersion', 'eventIds',
  ];
  if (!hasExactKeys(value, keys)
    || typeof value.logicalMessageId !== 'string' || !LOGICAL_ID.test(value.logicalMessageId)
    || typeof value.preferredObservationId !== 'string' || !V2_EVENT_ID.test(value.preferredObservationId)
    || typeof value.payloadConflict !== 'boolean'
    || typeof value.tombstoned !== 'boolean'
    || value.selectionVersion !== 'amf-observation-selection/v1'
    || !Array.isArray(value.eventIds) || value.eventIds.length < 1 || value.eventIds.length > 1_000
    || value.eventIds.some(id => typeof id !== 'string' || !V2_EVENT_ID.test(id))
    || new Set(value.eventIds).size !== value.eventIds.length) {
    fail('m4_v2_projector_logical_invalid');
  }
  return {
    logicalMessageId: value.logicalMessageId,
    preferredObservationId: value.preferredObservationId,
    payloadConflict: value.payloadConflict,
    tombstoned: value.tombstoned,
    selectionVersion: value.selectionVersion,
    eventIds: [...value.eventIds].sort(),
  };
}

function validVisibleText(value) {
  return typeof value === 'string'
    && [...value].length >= 1
    && [...value].length <= V3_TEXT_MAX
    && /\S/u.test(value);
}

function normalizeUtcTimestamp(value) {
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$/.exec(value);
  if (!match) fail('m4_v2_projector_observation_invalid');
  const fraction = match[7] ?? '';
  const parsed = Date.parse(value);
  const utc = new Date(parsed);
  if (!Number.isFinite(parsed) || Number.isNaN(utc.getTime())) fail('m4_v2_projector_observation_invalid');
  return `${utc.toISOString().slice(0, 19)}${fraction ? `.${fraction}` : ''}Z`;
}

function utcOrderKey(value) {
  const match = /^(.*?)(?:\.(\d{1,9}))?Z$/.exec(value);
  return `${match[1]}.${(match[2] ?? '').padEnd(9, '0')}`;
}

function copyObservation(value) {
  const keys = ['eventId', 'sessionId', 'sourceTag', 'migrationSequence', 'projection', 'visibleText'];
  if (!hasExactKeys(value, keys)
    || typeof value.eventId !== 'string' || !V2_EVENT_ID.test(value.eventId)
    || typeof value.sessionId !== 'string' || !V2_SESSION_ID.test(value.sessionId)
    || typeof value.sourceTag !== 'string' || !SOURCE_TAG.test(value.sourceTag)
    || !Number.isSafeInteger(value.migrationSequence) || value.migrationSequence < 0
    || (value.visibleText !== null && !validVisibleText(value.visibleText))) {
    fail('m4_v2_projector_observation_invalid');
  }
  let projection;
  try {
    projection = validateProjectionV2(value.projection);
  } catch {
    fail('m4_v2_projector_observation_invalid');
  }
  if (projection.eventId !== value.eventId || projection.sessionId !== value.sessionId) {
    fail('m4_v2_projector_observation_invalid');
  }
  return {
    eventId: value.eventId,
    sessionId: value.sessionId,
    sourceTag: value.sourceTag,
    migrationSequence: value.migrationSequence,
    projection,
    visibleText: value.visibleText,
    sourceOccurredAt: normalizeUtcTimestamp(projection.editedAt ?? projection.occurredAt),
  };
}

function compareTemporal(left, right) {
  return utcOrderKey(left.sourceOccurredAt).localeCompare(utcOrderKey(right.sourceOccurredAt))
    || left.migrationSequence - right.migrationSequence
    || left.eventId.localeCompare(right.eventId);
}

function isConversationObservation(observation) {
  const projection = observation.projection;
  if (projection.authoritativeDeletion) {
    return projection.contentType === 'none'
      && projection.hasContent === false
      && observation.visibleText === null;
  }
  if (!['user', 'assistant'].includes(projection.role)
    || !['inbound', 'outbound'].includes(projection.direction)
    || !['dm', 'group', 'channel', 'thread', 'session'].includes(projection.conversationKind)
    || (projection.role === 'user' && projection.direction !== 'inbound')
    || (projection.role === 'assistant' && projection.direction !== 'outbound')) {
    return false;
  }
  return projection.contentType === 'text' && validVisibleText(observation.visibleText);
}

function evidence(inputCount, eligibleCount, outputCount, deduplicatedCount, excludedCount, states) {
  return {
    inputCount,
    eligibleCount,
    outputCount,
    deduplicatedCount,
    excludedCount,
    states: {
      active: states.active,
      edited: states.edited,
      replacement: 0,
      tombstone: states.tombstone,
      conflict: states.conflict,
    },
  };
}

function excluded(reason, inputCount, eligibleCount, excludedCount) {
  if (!EXCLUSION_REASONS.has(reason)) fail('m4_v2_projector_internal_invalid');
  return {
    schema: SCHEMA,
    outcome: 'excluded',
    reason,
    evidence: evidence(inputCount, eligibleCount, 0, 0, excludedCount, {
      active: 0, edited: 0, tombstone: 0, conflict: 0,
    }),
    events: [],
  };
}

function recomputeLogical(logical, observations) {
  const selected = selectLogicalMessage(observations.map(observation => ({
    eventId: observation.eventId,
    projection: observation.projection,
  })));
  const membership = observations.map(observation => observation.eventId).sort();
  if (selected.logicalMessageId !== logical.logicalMessageId
    || selected.preferredObservationId !== logical.preferredObservationId
    || selected.payloadConflict !== logical.payloadConflict
    || selected.tombstoned !== logical.tombstoned
    || selected.selectionVersion !== logical.selectionVersion
    || canonicalJson(membership) !== canonicalJson(logical.eventIds)) {
    fail('m4_v2_projector_logical_drift');
  }
}

function chooseRepresentatives(observations) {
  const byDigest = new Map();
  for (const observation of observations) {
    const digest = observation.projection.normalizedPayloadDigest;
    const prior = byDigest.get(digest);
    if (!prior || compareObservations(observation, prior) < 0) byDigest.set(digest, observation);
  }
  return [...byDigest.values()].sort(compareTemporal);
}

function assertDigestBucketSemantics(observations) {
  const representatives = new Map();
  for (const observation of observations) {
    const digest = observation.projection.normalizedPayloadDigest;
    const first = representatives.get(digest);
    if (!first) {
      representatives.set(digest, observation);
      continue;
    }
    if (observation.projection.role !== first.projection.role
      || observation.projection.direction !== first.projection.direction
      || observation.projection.conversationKind !== first.projection.conversationKind
      || canonicalJson(observation.projection.contextTags) !== canonicalJson(first.projection.contextTags)) {
      fail('m4_v2_projector_digest_semantics_invalid');
    }
  }
}

function chainMarker(representatives) {
  if (representatives.length < 2) return null;
  const later = representatives.slice(1);
  const nativeRevision = later.every(item => item.projection.nativeRevision !== null);
  const editedAt = later.every(item => item.projection.editedAt !== null);
  if (!nativeRevision && !editedAt) return null;
  return nativeRevision ? 'nativeRevision' : 'editedAt';
}

function isEditChain(representatives) {
  if (representatives.length < 2) return true;
  if (!representatives.every(item => item.projection.observationClass === 'native')
    || new Set(representatives.map(item => item.projection.sourceKind)).size !== 1) {
    return false;
  }
  const first = representatives[0];
  if (!representatives.every(item => item.projection.role === first.projection.role
    && item.projection.direction === first.projection.direction
    && item.projection.conversationKind === first.projection.conversationKind
    && item.sourceTag === first.sourceTag
    && canonicalJson(item.projection.contextTags) === canonicalJson(first.projection.contextTags))) {
    return false;
  }
  const marker = chainMarker(representatives);
  if (marker === null) return false;
  const markerValue = item => marker === 'editedAt'
    ? (item.projection.editedAt === null ? null : utcOrderKey(item.sourceOccurredAt))
    : item.projection.nativeRevision;
  let priorMarker = markerValue(representatives[0]);
  if (priorMarker !== null && marker === 'nativeRevision' && !Number.isFinite(priorMarker)) return false;
  for (const item of representatives.slice(1)) {
    const value = markerValue(item);
    if (marker === 'nativeRevision' && !Number.isFinite(value)) return false;
    if (marker === 'editedAt' && typeof value !== 'string') return false;
    if (priorMarker !== null && value <= priorMarker) return false;
    priorMarker = value;
  }
  return representatives.every((item, index) => index === 0 || compareTemporal(representatives[index - 1], item) < 0);
}

async function createProjectedEvent({
  observation,
  semanticObservation = observation,
  eventId,
  conversationId,
  sourceInstanceId,
  state,
  revision,
  previousId,
  conflicts,
  integrityFor,
}) {
  const sourceOccurredAt = observation.sourceOccurredAt;
  const integrityInput = { legacyEventId: observation.eventId, eventId, state, revision };
  let integrity;
  try {
    integrity = await integrityFor(integrityInput);
  } catch {
    fail('m4_v2_projector_integrity_unavailable');
  }
  const payload = {
    eventId,
    conversationId,
    sourceInstanceId,
    role: semanticObservation.projection.role,
    sourceOccurredAt,
    occurredAt: sourceOccurredAt,
    ordering: { sourceSequence: observation.migrationSequence },
    direction: semanticObservation.projection.direction,
    conversationKind: semanticObservation.projection.conversationKind,
    authorizationContextTags: structuredClone(semanticObservation.projection.contextTags),
    state,
    revision,
  };
  if (state !== 'tombstone') payload.visibleText = observation.visibleText;
  if (state === 'edited') payload.replacesEventId = previousId;
  if (state === 'tombstone') payload.tombstonesEventId = previousId;
  if (state === 'conflict') payload.conflictsWithEventIds = [...conflicts].sort();
  try {
    return createConversationEvent(payload, integrity);
  } catch {
    fail('m4_v2_projector_event_invalid');
  }
}

function identityCollector(value) {
  if (value === undefined || value === null) return null;
  if (!hasExactKeys(value, ['accept']) || typeof value.accept !== 'function') {
    fail('m4_v2_projector_identity_collector_invalid');
  }
  return value;
}

function exactEventReferenceLegacyId(eventId, byV3EventId) {
  if (eventId === null) return null;
  const legacyEventId = byV3EventId.get(eventId);
  if (legacyEventId === undefined) fail('m4_v2_projector_identity_binding_invalid');
  return legacyEventId;
}

// This is a content-free observation of the exact projector result. It is
// deliberately not an attestation: only a later trusted traversal can prove
// that every callback originated from this projector invocation.
function projectorIdentityBlock({ sessionId, conversationId, sourceTags, selected, events }) {
  if (!Array.isArray(selected) || !Array.isArray(events) || selected.length !== events.length) {
    fail('m4_v2_projector_identity_binding_invalid');
  }
  const byV3EventId = new Map();
  for (const observation of selected) {
    const eventId = deriveM4V3EventIdFromLegacyEventId(observation.eventId);
    if (byV3EventId.has(eventId)) fail('m4_v2_projector_identity_binding_invalid');
    byV3EventId.set(eventId, observation.eventId);
  }
  const entries = events.map(event => {
    const legacyEventId = byV3EventId.get(event.eventId);
    if (legacyEventId === undefined || event.conversationId !== conversationId
      || event.sourceInstanceId !== deriveSourceInstanceId(sessionId, sourceTags)) {
      fail('m4_v2_projector_identity_binding_invalid');
    }
    return {
      legacyEventId,
      legacySessionId: sessionId,
      eventId: event.eventId,
      conversationId,
      sourceInstanceId: event.sourceInstanceId,
      sourceTags: [...sourceTags],
      conversationKind: event.conversationKind,
      authorizationContextTags: structuredClone(event.authorizationContextTags),
      role: event.role,
      direction: event.direction,
      state: event.state,
      revision: event.revision,
      replacesLegacyEventId: exactEventReferenceLegacyId(event.replacesEventId ?? null, byV3EventId),
      tombstonesLegacyEventId: exactEventReferenceLegacyId(event.tombstonesEventId ?? null, byV3EventId),
      conflictsWithLegacyEventIds: (event.conflictsWithEventIds ?? []).map(item => exactEventReferenceLegacyId(item, byV3EventId)).sort(),
    };
  });
  const first = entries[0];
  let sessionContextTags;
  try { sessionContextTags = sessionContextBinding(first.authorizationContextTags); }
  catch { fail('m4_v2_projector_identity_binding_invalid'); }
  if (entries.some(entry => entry.conversationKind !== first.conversationKind
    || canonicalJson(sessionContextBinding(entry.authorizationContextTags)) !== canonicalJson(sessionContextTags))) {
    fail('m4_v2_projector_identity_binding_invalid');
  }
  return {
    schema: 'amf.m4-cross-phase-projector-identity-block/v1',
    session: { legacySessionId: sessionId, conversationId, conversationKind: first.conversationKind, sessionContextTags },
    events: entries,
  };
}

export async function projectM4V2LogicalGroup({ logical, observations, integrityFor, identityCollector: collectorInput = null } = {}) {
  if (typeof integrityFor !== 'function' || !Array.isArray(observations) || observations.length < 1 || observations.length > 1_000) {
    fail('m4_v2_projector_request_invalid');
  }
  const safeLogical = copyLogical(logical);
  const identitySink = identityCollector(collectorInput);
  const safeObservations = observations.map(copyObservation);
  if (new Set(safeObservations.map(item => item.eventId)).size !== safeObservations.length
    || new Set(safeObservations.map(item => item.migrationSequence)).size !== safeObservations.length
    || new Set(safeObservations.map(item => item.sessionId)).size !== 1
    || safeObservations.some(item => item.projection.logicalMessageId !== safeLogical.logicalMessageId)) {
    fail('m4_v2_projector_observation_invalid');
  }
  recomputeLogical(safeLogical, safeObservations);

  const preferred = safeObservations.find(item => item.eventId === safeLogical.preferredObservationId);
  if (!isConversationObservation(preferred)) {
    return excluded('preferred_ineligible', safeObservations.length, 0, safeObservations.length);
  }
  const eligible = safeObservations.filter(isConversationObservation);
  const nonDeletion = eligible.filter(item => !item.projection.authoritativeDeletion);
  const deletion = preferred.projection.authoritativeDeletion ? preferred : null;
  const deletions = safeObservations.filter(item => item.projection.authoritativeDeletion);
  const deletionCandidates = deletions.filter(isConversationObservation);
  if (nonDeletion.length === 0) {
    return excluded('deletion_without_history', safeObservations.length, eligible.length, safeObservations.length);
  }

  assertDigestBucketSemantics(nonDeletion);
  const representatives = chooseRepresentatives(nonDeletion);
  if (representatives.length > 33) fail('m4_v2_projector_conflict_bound_invalid');
  if (deletion !== null) {
    for (const other of deletions) {
      if (other.eventId !== deletion.eventId
        && other.projection.normalizedPayloadDigest !== deletion.projection.normalizedPayloadDigest) {
        fail('m4_v2_projector_deletion_conflict');
      }
    }
  }
  const chain = isEditChain(representatives);
  if (deletion !== null) {
    if (!chain) fail('m4_v2_projector_deletion_conflict_history');
    const predecessor = representatives.at(-1);
    if (deletion.projection.sourceKind !== predecessor.projection.sourceKind
      || deletion.sourceTag !== predecessor.sourceTag
      || canonicalJson(deletion.projection.contextTags) !== canonicalJson(predecessor.projection.contextTags)) {
      fail('m4_v2_projector_deletion_binding_invalid');
    }
    if (compareTemporal(predecessor, deletion) >= 0) {
      fail('m4_v2_projector_deletion_order_invalid');
    }
  }
  const sessionId = safeObservations[0].sessionId;
  const conversationId = deriveConversationId(sessionId);
  const sourceTags = [...new Set([
    ...representatives.map(item => item.sourceTag),
    ...(deletion === null ? [] : [deletion.sourceTag]),
  ])].sort();
  const sourceInstanceId = deriveSourceInstanceId(sessionId, sourceTags);
  const events = [];
  const states = { active: 0, edited: 0, tombstone: 0, conflict: 0 };

  for (const [index, observation] of representatives.entries()) {
    const state = index === 0 ? 'active' : chain ? 'edited' : 'conflict';
    const event = await createProjectedEvent({
      observation,
      eventId: deriveM4V3EventIdFromLegacyEventId(observation.eventId),
      conversationId,
      sourceInstanceId,
      state,
      revision: state === 'edited' ? index + 1 : 1,
      previousId: events.at(-1)?.eventId,
      conflicts: events.map(item => item.eventId),
      integrityFor,
    });
    events.push(event);
    states[state] += 1;
  }

  if (deletion !== null) {
    const event = await createProjectedEvent({
      observation: deletion,
      semanticObservation: representatives.at(-1),
      eventId: deriveM4V3EventIdFromLegacyEventId(deletion.eventId),
      conversationId,
      sourceInstanceId,
      state: 'tombstone',
      revision: 1,
      previousId: events.at(-1).eventId,
      conflicts: [],
      integrityFor,
    });
    events.push(event);
    states.tombstone += 1;
  }

  events.sort(compareConversationEvents);
  if (identitySink !== null) {
    const selected = [...representatives, ...(deletion === null ? [] : [deletion])];
    const block = projectorIdentityBlock({ sessionId, conversationId, sourceTags, selected, events });
    try { await identitySink.accept(structuredClone(block)); }
    catch { fail('m4_v2_projector_identity_collector_failed'); }
  }
  return {
    schema: SCHEMA,
    outcome: 'projected',
    reason: null,
    evidence: evidence(
      safeObservations.length,
      eligible.length,
      events.length,
      nonDeletion.length - representatives.length
        + Math.max(0, deletionCandidates.length - (deletion === null ? 0 : 1)),
      safeObservations.length - eligible.length,
      states,
    ),
    events,
  };
}
