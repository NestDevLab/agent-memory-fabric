import crypto from 'node:crypto';

import { canonicalJson, strictIsoTimestamp } from './transcripts/canonical.mjs';

export const RAW_PROJECTION_V2_SCHEMA = 'amf.raw-event-projection/v2';
export const LOGICAL_DERIVATION_VERSION = 'amf-logical-message/v1';
export const OBSERVATION_SELECTION_VERSION = 'amf-observation-selection/v1';
export const OBSERVATION_NORMALIZATION_VERSION = 'amf-observation-normalization/v1';
export const SESSION_DERIVATION_VERSION = 'amf-session/v2';
export const EVENT_DERIVATION_VERSION = 'amf-observation/v2';

const SOURCE_KINDS = new Set(['codex', 'claude', 'hermes', 'openclaw', 'principia']);
const OBSERVATION_CLASSES = new Set(['native', 'delivery-handoff', 'provisional']);
const DIRECTIONS = new Set(['inbound', 'outbound', 'internal', 'unknown']);
const CONVERSATION_KINDS = new Set(['dm', 'group', 'channel', 'thread', 'session', 'unknown']);
const ROLES = new Set(['user', 'assistant', 'system', 'tool', 'unknown']);
const CONTENT_TYPES = new Set(['text', 'structured', 'tool', 'mixed', 'none', 'unknown']);
const CONTEXT_TAG_KEYS = new Set(['actor', 'sender', 'conversation', 'room', 'person', 'relationship', 'thread']);
const OPAQUE_TAG = /^hmac-sha256:[A-Za-z0-9._-]{1,128}:[a-f0-9]{64}$/;
const LOGICAL_ID = /^lmsg_[a-f0-9]{64}$/;
const SAFE_ID = /^(?:evt|ses)_[a-f0-9]{64}$/;
const ALLOWED_FIELDS = [
  'schema', 'eventId', 'sessionId', 'logicalMessageId', 'logicalMessageAliases',
  'derivationVersion', 'keyVersion', 'sourceKind', 'observationClass', 'direction',
  'conversationKind', 'contextTags', 'subtype', 'occurredAt', 'editedAt',
  'nativeRevision', 'sourceSequence', 'authoritativeDeletion', 'role', 'contentType',
  'contentParts', 'hasContent', 'normalizationVersion', 'normalizedPayloadDigest'
];

export function normalizeContextTags(contextTags) {
  if (!contextTags || typeof contextTags !== 'object' || Array.isArray(contextTags)) throw new Error('raw_projection_invalid');
  const normalized = {};
  for (const key of Object.keys(contextTags).sort()) {
    const values = contextTags[key];
    if (!CONTEXT_TAG_KEYS.has(key) || !Array.isArray(values) || values.length === 0 || values.some(tag => !OPAQUE_TAG.test(tag))) throw new Error('raw_projection_invalid');
    const exact = [...new Set(values)].sort();
    if (exact.length !== values.length || exact.some((value, index) => value !== values[index])) throw new Error('raw_projection_invalid');
    normalized[key] = exact;
  }
  if (!normalized.sender || !normalized.conversation) throw new Error('raw_projection_invalid');
  return normalized;
}

export function contextTagsIntersect(stored, presented) {
  const left = normalizeContextTags(stored);
  const right = normalizeContextTags(presented);
  const routingKeys = Object.keys(left).filter(key => ['conversation', 'room', 'person', 'relationship', 'thread'].includes(key));
  if (routingKeys.length === 0) return false;
  return routingKeys.every(key => Array.isArray(right[key]) && left[key].some(tag => right[key].includes(tag)));
}

function exactKeys(value, allowed) {
  return value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join('\0') === [...allowed].sort().join('\0');
}

function parseKey(value) {
  const raw = String(value || '');
  if (/^[a-f0-9]{64}$/i.test(raw)) return Buffer.from(raw, 'hex');
  const decoded = Buffer.from(raw, 'base64');
  if (decoded.length !== 32 || decoded.toString('base64') !== raw) throw new Error('logical_message_key_invalid');
  return decoded;
}

export function normalizeLogicalMessageKeyRing(value) {
  if (!value?.currentKeyVersion || !value?.keys || typeof value.keys !== 'object') throw new Error('logical_message_keys_unconfigured');
  const keys = new Map(Object.entries(value.keys).map(([version, key]) => {
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(version)) throw new Error('logical_message_key_version_invalid');
    return [version, parseKey(key)];
  }));
  if (!keys.has(value.currentKeyVersion)) throw new Error('logical_message_current_key_missing');
  return { currentKeyVersion: value.currentKeyVersion, keys };
}

export function opaqueContextTag(namespace, literal, key, keyVersion) {
  const digest = crypto.createHmac('sha256', parseKey(key)).update(canonicalJson([namespace, String(literal)]), 'utf8').digest('hex');
  return `hmac-sha256:${keyVersion}:${digest}`;
}

export function deriveSessionIdV2({ sourceKind, nativeSessionId = null, conversationTag = null }) {
  if (!SOURCE_KINDS.has(sourceKind) || (!nativeSessionId && !OPAQUE_TAG.test(String(conversationTag || '')))) throw new Error('raw_session_derivation_invalid');
  const material = canonicalJson([SESSION_DERIVATION_VERSION, sourceKind, nativeSessionId ? ['native', String(nativeSessionId)] : ['conversation', conversationTag]]);
  return `ses_${crypto.createHash('sha256').update(material, 'utf8').digest('hex')}`;
}

export function deriveEventIdV2({ sourceKind, nativeSessionId = null, nativeEventId = null, observationClass, rawBytes = null }) {
  if (!SOURCE_KINDS.has(sourceKind) || !OBSERVATION_CLASSES.has(observationClass) || (!nativeEventId && !Buffer.isBuffer(rawBytes))) throw new Error('raw_event_derivation_invalid');
  const identity = nativeEventId ? ['native', String(nativeSessionId || ''), String(nativeEventId)] : ['bytes', crypto.createHash('sha256').update(rawBytes).digest('hex')];
  return `evt_${crypto.createHash('sha256').update(canonicalJson([EVENT_DERIVATION_VERSION, sourceKind, observationClass, identity]), 'utf8').digest('hex')}`;
}

function strongTuple(input) {
  const native = input.nativePlatform && input.nativeMessageId
    ? ['native', input.nativePlatform, input.nativeConversationId, input.nativeMessageId]
    : null;
  const delivery = input.deliveryCorrelationId ? ['delivery', input.deliveryCorrelationId] : null;
  if (!native && !delivery) throw new Error('logical_message_strong_identifier_required');
  return native || delivery;
}

export function deriveLogicalMessageIds(input, keyRing) {
  const normalized = keyRing?.keys instanceof Map ? keyRing : normalizeLogicalMessageKeyRing(keyRing);
  const tuple = strongTuple(input);
  const material = canonicalJson({
    derivationVersion: LOGICAL_DERIVATION_VERSION,
    canonicalSenderIdentity: input.canonicalSenderIdentity,
    senderTag: input.senderTag,
    conversationTag: input.conversationTag,
    direction: input.direction,
    tuple
  });
  if (!input.canonicalSenderIdentity || !OPAQUE_TAG.test(input.senderTag) || !OPAQUE_TAG.test(input.conversationTag) || !DIRECTIONS.has(input.direction)) throw new Error('logical_message_derivation_invalid');
  const ids = [...normalized.keys].map(([version, key]) => ({
    keyVersion: version,
    logicalMessageId: `lmsg_${crypto.createHmac('sha256', key).update(material, 'utf8').digest('hex')}`
  }));
  const preferred = ids.find(item => item.keyVersion === normalized.currentKeyVersion);
  return { ...preferred, aliases: ids.filter(item => item.logicalMessageId !== preferred.logicalMessageId) };
}

export function validateProjectionV2(projection) {
  if (!exactKeys(projection, ALLOWED_FIELDS)) throw new Error('raw_projection_invalid');
  if (projection.schema !== RAW_PROJECTION_V2_SCHEMA || !SAFE_ID.test(projection.eventId) || !SAFE_ID.test(projection.sessionId) || !LOGICAL_ID.test(projection.logicalMessageId)) throw new Error('raw_projection_invalid');
  if (!Array.isArray(projection.logicalMessageAliases) || projection.logicalMessageAliases.some(item => !exactKeys(item, ['keyVersion', 'logicalMessageId']) || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(item.keyVersion) || !LOGICAL_ID.test(item.logicalMessageId))) throw new Error('raw_projection_invalid');
  if (projection.derivationVersion !== LOGICAL_DERIVATION_VERSION || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(projection.keyVersion)) throw new Error('raw_projection_invalid');
  if (!SOURCE_KINDS.has(projection.sourceKind) || !OBSERVATION_CLASSES.has(projection.observationClass) || !DIRECTIONS.has(projection.direction) || !CONVERSATION_KINDS.has(projection.conversationKind)) throw new Error('raw_projection_invalid');
  normalizeContextTags(projection.contextTags);
  if (typeof projection.subtype !== 'string' || projection.subtype.length < 1 || projection.subtype.length > 128 || !/^[A-Za-z0-9._:-]+$/.test(projection.subtype)) throw new Error('raw_projection_invalid');
  for (const field of ['occurredAt', 'editedAt']) if (projection[field] !== null && strictIsoTimestamp(projection[field]) !== projection[field]) throw new Error('raw_projection_invalid');
  if (projection.nativeRevision !== null && (!Number.isSafeInteger(projection.nativeRevision) || projection.nativeRevision < 0)) throw new Error('raw_projection_invalid');
  if (projection.sourceSequence !== null && (!Number.isSafeInteger(projection.sourceSequence) || projection.sourceSequence < 0)) throw new Error('raw_projection_invalid');
  if (typeof projection.authoritativeDeletion !== 'boolean' || !ROLES.has(projection.role) || !CONTENT_TYPES.has(projection.contentType)) throw new Error('raw_projection_invalid');
  if (projection.authoritativeDeletion && !(projection.observationClass === 'native' && ['codex', 'claude', 'hermes', 'openclaw'].includes(projection.sourceKind))) throw new Error('raw_projection_invalid');
  if (!Number.isSafeInteger(projection.contentParts) || projection.contentParts < 0 || projection.contentParts > 10000 || projection.hasContent !== (projection.contentParts > 0)) throw new Error('raw_projection_invalid');
  if (projection.normalizationVersion !== OBSERVATION_NORMALIZATION_VERSION || !/^hmac-sha256:[A-Za-z0-9._-]{1,128}:[a-f0-9]{64}$/.test(projection.normalizedPayloadDigest)) throw new Error('raw_projection_invalid');
  return projection;
}

export function observationAuthority(projection) {
  if (projection.observationClass === 'native' && ['codex', 'claude', 'hermes', 'openclaw'].includes(projection.sourceKind)) return 400;
  if (projection.observationClass === 'delivery-handoff' && projection.sourceKind === 'principia') return 200;
  return 100;
}

function revisionValue(projection) {
  if (projection.editedAt) return Date.parse(projection.editedAt);
  return projection.nativeRevision ?? -1;
}

export function compareObservations(left, right) {
  if (left.projection.authoritativeDeletion !== right.projection.authoritativeDeletion) return left.projection.authoritativeDeletion ? -1 : 1;
  const authority = observationAuthority(right.projection) - observationAuthority(left.projection);
  if (authority) return authority;
  const revision = revisionValue(right.projection) - revisionValue(left.projection);
  if (revision) return revision;
  const sequence = (right.projection.sourceSequence ?? -1) - (left.projection.sourceSequence ?? -1);
  if (sequence) return sequence;
  return left.eventId.localeCompare(right.eventId);
}

export function selectLogicalMessage(observations) {
  if (!Array.isArray(observations) || observations.length === 0) throw new Error('logical_message_observations_required');
  const logicalIds = new Set(observations.map(item => item.projection.logicalMessageId));
  if (logicalIds.size !== 1) throw new Error('logical_message_mismatch');
  const ordered = [...observations].sort(compareObservations);
  const digests = new Set(observations.filter(item => !item.projection.authoritativeDeletion).map(item => item.projection.normalizedPayloadDigest));
  return {
    logicalMessageId: ordered[0].projection.logicalMessageId,
    preferredObservationId: ordered[0].eventId,
    payloadConflict: digests.size > 1,
    tombstoned: ordered[0].projection.authoritativeDeletion,
    selectionVersion: OBSERVATION_SELECTION_VERSION
  };
}
