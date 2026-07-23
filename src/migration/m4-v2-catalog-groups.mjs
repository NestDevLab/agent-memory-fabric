import { validateProjectionV2 } from '../ingest/raw-projection-v2.mjs';
import { strictIsoTimestamp } from '../ingest/transcripts/canonical.mjs';

const LOGICAL_MESSAGE_ID = /^lmsg_[a-f0-9]{64}$/;
const EVENT_ID = /^evt_[a-f0-9]{64}$/;
const SESSION_ID = /^ses_[a-f0-9]{64}$/;
const CONTENT_ID = /^[a-f0-9]{64}$/;
const PAYLOAD_DIGEST = /^hmac-sha256:v1:[a-f0-9]{64}$/;
const CATALOG_TAG = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}:[a-f0-9]{64}$/;
export const M4_V2_LOGICAL_GROUP_MAX_OBSERVATIONS = 8_192;

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

export function validateM4V2LogicalGroupRequest(input = {}) {
  if (!isPlainObject(input) || Object.keys(input).some(key => !['after', 'limit'].includes(key))) {
    fail('m4_v2_catalog_request_invalid');
  }
  const { after = null, limit = 50 } = input;
  if ((after !== null && (typeof after !== 'string' || !LOGICAL_MESSAGE_ID.test(after)))
    || !Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
    fail('m4_v2_catalog_request_invalid');
  }
  return { after, limit };
}

function copyLogical(value) {
  const keys = [
    'logicalMessageId', 'preferredObservationId', 'payloadConflict',
    'tombstoned', 'selectionVersion', 'eventIds',
  ];
  if (!hasExactKeys(value, keys)
    || typeof value.logicalMessageId !== 'string' || !LOGICAL_MESSAGE_ID.test(value.logicalMessageId)
    || typeof value.preferredObservationId !== 'string' || !EVENT_ID.test(value.preferredObservationId)
    || typeof value.payloadConflict !== 'boolean'
    || typeof value.tombstoned !== 'boolean'
    || value.selectionVersion !== 'amf-observation-selection/v1'
    || !Array.isArray(value.eventIds)
    || value.eventIds.length < 1
    || value.eventIds.length > M4_V2_LOGICAL_GROUP_MAX_OBSERVATIONS
    || value.eventIds.some(eventId => typeof eventId !== 'string' || !EVENT_ID.test(eventId))
    || new Set(value.eventIds).size !== value.eventIds.length
    || !value.eventIds.includes(value.preferredObservationId)) {
    fail('m4_v2_catalog_group_invalid');
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

function copyObservation(value, logicalMessageId) {
  const keys = [
    'eventId', 'sessionId', 'logicalMessageId', 'contentId', 'payloadDigest',
    'projection', 'ownerTag', 'sourceTag', 'createdAt',
  ];
  if (!hasExactKeys(value, keys)
    || typeof value.eventId !== 'string' || !EVENT_ID.test(value.eventId)
    || typeof value.sessionId !== 'string' || !SESSION_ID.test(value.sessionId)
    || value.logicalMessageId !== logicalMessageId
    || typeof value.contentId !== 'string' || !CONTENT_ID.test(value.contentId)
    || typeof value.payloadDigest !== 'string' || !PAYLOAD_DIGEST.test(value.payloadDigest)
    || typeof value.ownerTag !== 'string' || !CATALOG_TAG.test(value.ownerTag)
    || typeof value.sourceTag !== 'string' || !CATALOG_TAG.test(value.sourceTag)
    || typeof value.createdAt !== 'string' || strictIsoTimestamp(value.createdAt) !== value.createdAt) {
    fail('m4_v2_catalog_group_invalid');
  }
  let projection;
  try {
    projection = validateProjectionV2(value.projection);
  } catch {
    fail('m4_v2_catalog_group_invalid');
  }
  const signedLogicalIds = new Set([
    projection.logicalMessageId,
    ...projection.logicalMessageAliases.map(alias => alias.logicalMessageId),
  ]);
  if (projection.eventId !== value.eventId
    || projection.sessionId !== value.sessionId
    || !signedLogicalIds.has(logicalMessageId)) {
    fail('m4_v2_catalog_group_invalid');
  }
  return {
    eventId: value.eventId,
    sessionId: value.sessionId,
    logicalMessageId: value.logicalMessageId,
    contentId: value.contentId,
    payloadDigest: value.payloadDigest,
    projection: structuredClone(projection),
    ownerTag: value.ownerTag,
    sourceTag: value.sourceTag,
    createdAt: value.createdAt,
  };
}

export function buildM4V2LogicalGroup(logical, observations) {
  const safeLogical = copyLogical(logical);
  if (!Array.isArray(observations) || observations.length !== safeLogical.eventIds.length) {
    fail('m4_v2_catalog_group_invalid');
  }
  const safeObservations = observations
    .map(observation => copyObservation(observation, safeLogical.logicalMessageId))
    .sort((left, right) => left.eventId.localeCompare(right.eventId));
  const observationIds = safeObservations.map(observation => observation.eventId);
  if (new Set(observationIds).size !== observationIds.length
    || observationIds.length !== safeLogical.eventIds.length
    || observationIds.some((eventId, index) => eventId !== safeLogical.eventIds[index])) {
    fail('m4_v2_catalog_group_invalid');
  }
  return { logical: safeLogical, observations: safeObservations };
}
