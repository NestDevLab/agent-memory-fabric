import crypto from 'node:crypto';

import { canonicalJson, strictIsoTimestamp } from './transcripts/canonical.mjs';
import { OBSERVATION_NORMALIZATION_VERSION, deriveEventIdV2, deriveLogicalMessageIds, deriveSessionIdV2, normalizeLogicalMessageKeyRing, validateProjectionV2 } from './raw-projection-v2.mjs';

export const RAW_EVENT_CIPHERTEXT_VERSION = 3;
export const RAW_EVENT_CIPHERTEXT_SCHEMA = 'amf.raw-event-ciphertext/v1';
const SAFE_EVENT_ID = /^evt_[a-f0-9]{64}$/;
const SAFE_SESSION_ID = /^ses_[a-f0-9]{64}$/;
const SAFE_KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const SAFE_SOURCE_INSTANCE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const HKDF_SALT = Buffer.from('agent-memory-fabric/outbox/v1', 'utf8');

function parseMasterKey(value) {
  const raw = String(value || '');
  if (/^[a-f0-9]{64}$/i.test(raw)) return Buffer.from(raw, 'hex');
  if (!/^[A-Za-z0-9+/]{43}=$/.test(raw)) throw new Error('raw_ingest_key_invalid');
  const decoded = Buffer.from(raw, 'base64');
  if (decoded.length !== 32 || decoded.toString('base64') !== raw) throw new Error('raw_ingest_key_invalid');
  return decoded;
}

export function normalizeIngestKeyRing(keyRing) {
  if (!keyRing?.keys || typeof keyRing.keys !== 'object') throw new Error('raw_ingest_unconfigured');
  const keys = new Map(Object.entries(keyRing.keys).map(([id, value]) => {
    if (!SAFE_KEY_ID.test(id)) throw new Error('raw_ingest_key_invalid');
    const master = parseMasterKey(value);
    return [id, Buffer.from(crypto.hkdfSync('sha256', master, HKDF_SALT, Buffer.from('aes-256-gcm', 'utf8'), 32))];
  }));
  if (keys.size === 0 || !keyRing.digestKey) throw new Error('raw_ingest_unconfigured');
  const digestMaster = parseMasterKey(keyRing.digestKey);
  const digestKey = Buffer.from(crypto.hkdfSync('sha256', digestMaster, HKDF_SALT, Buffer.from('stable-event-digest/v1', 'utf8'), 32));
  const authorizations = new Map();
  for (const keyId of keys.keys()) {
    const rule = keyRing.authorizations?.[keyId];
    if (!rule || !Array.isArray(rule.actors) || !Array.isArray(rule.sourceInstances) || rule.actors.length === 0 || rule.sourceInstances.length === 0) throw new Error('raw_ingest_key_authorization_invalid');
    authorizations.set(keyId, { actors: new Set(rule.actors.map(String)), sourceInstances: new Set(rule.sourceInstances.map(String)) });
  }
  const logicalKeys = keyRing.logicalMessageKeys
    ? normalizeLogicalMessageKeyRing(keyRing.logicalMessageKeys)
    : { currentKeyVersion: 'v1', keys: new Map([['v1', digestMaster]]) };
  return { keys, digestKey, authorizations, logicalKeys };
}

export function projectionDigest(projection) {
  return crypto.createHash('sha256').update(canonicalJson(projection), 'utf8').digest('hex');
}

export function stablePayloadDigest(item, digestKey) {
  const hex = crypto.createHmac('sha256', digestKey).update(canonicalJson(item), 'utf8').digest('hex');
  return `hmac-sha256:v1:${hex}`;
}

export function normalizedObservationDigest(item, digestKey) {
  const normalized = item?.event?.normalized;
  if (!normalized || typeof normalized !== 'object' || Array.isArray(normalized)) throw new Error('raw_observation_normalization_invalid');
  const hex = crypto.createHmac('sha256', digestKey)
    .update(canonicalJson([OBSERVATION_NORMALIZATION_VERSION, normalized]), 'utf8')
    .digest('hex');
  return `hmac-sha256:v1:${hex}`;
}

function rawObservationBytes(item) {
  const line = item?.event?.raw?.line;
  if (typeof line !== 'string') throw new Error('raw_event_derivation_invalid');
  const decoded = Buffer.from(line, 'base64');
  if (!decoded.length || decoded.toString('base64') !== line) throw new Error('raw_event_derivation_invalid');
  return decoded;
}

function verifyProjectionDerivations(item, projection, digestKey) {
  const sourceKind = projection.sourceKind;
  const derivation = item?.event?.derivation;
  const sessionCandidates = new Set([
    deriveSessionIdV2({ sourceKind, conversationTag: projection.contextTags.conversation[0] })
  ]);
  const eventCandidates = new Set([
    deriveEventIdV2({ sourceKind, observationClass: projection.observationClass, rawBytes: rawObservationBytes(item) })
  ]);
  if (derivation !== undefined) {
    if (!derivation || typeof derivation !== 'object' || Array.isArray(derivation)
      || Object.keys(derivation).some(key => !['nativeSessionId', 'nativeEventId'].includes(key))) throw new Error('raw_event_derivation_invalid');
    if (derivation.nativeSessionId) sessionCandidates.add(deriveSessionIdV2({ sourceKind, nativeSessionId: String(derivation.nativeSessionId) }));
    if (derivation.nativeEventId) eventCandidates.add(deriveEventIdV2({ sourceKind, nativeSessionId: derivation.nativeSessionId ? String(derivation.nativeSessionId) : null, nativeEventId: String(derivation.nativeEventId), observationClass: projection.observationClass }));
  }
  if (!sessionCandidates.has(projection.sessionId) || !eventCandidates.has(projection.eventId)) throw new Error('raw_event_derivation_invalid');
  if (normalizedObservationDigest(item, digestKey) !== projection.normalizedPayloadDigest) throw new Error('raw_observation_normalization_invalid');
}

export function rawEventAad({ eventId, sessionId, keyId, projectionSha256, payloadDigest, sourceInstanceId, actorId }) {
  return Buffer.from(canonicalJson({
    actorId, eventId, keyId, payloadDigest, projectionSha256, schema: RAW_EVENT_CIPHERTEXT_SCHEMA, sourceInstanceId,
    sessionId, version: RAW_EVENT_CIPHERTEXT_VERSION
  }), 'utf8');
}

function canonicalBase64(value, bytes = null) {
  if (typeof value !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) return false;
  const decoded = Buffer.from(value, 'base64');
  return decoded.toString('base64') === value && (bytes === null || decoded.length === bytes);
}

export function validateSafeProjection(projection) {
  if (projection?.schema === 'amf.raw-event-projection/v2') return validateProjectionV2(projection);
  const allowed = ['schema', 'eventId', 'sessionId', 'runtime', 'subtype', 'occurredAt', 'role', 'contentType', 'contentParts', 'hasContent'];
  if (!projection || Object.keys(projection).sort().join('\0') !== allowed.sort().join('\0')) throw new Error('raw_projection_invalid');
  if (projection.schema !== 'amf.raw-event-projection/v1' || !SAFE_EVENT_ID.test(projection.eventId) || !SAFE_SESSION_ID.test(projection.sessionId)) throw new Error('raw_projection_invalid');
  if (!['codex', 'claude'].includes(projection.runtime) || !safeSubtype(projection.runtime, projection.subtype)) throw new Error('raw_projection_invalid');
  if (projection.occurredAt !== null && strictIsoTimestamp(projection.occurredAt) !== projection.occurredAt) throw new Error('raw_projection_invalid');
  if (!['user', 'assistant', 'system', 'tool', 'unknown'].includes(projection.role)) throw new Error('raw_projection_invalid');
  if (!['text', 'structured', 'tool', 'mixed', 'none', 'unknown'].includes(projection.contentType)) throw new Error('raw_projection_invalid');
  if (!Number.isSafeInteger(projection.contentParts) || projection.contentParts < 0 || projection.contentParts > 10000 || projection.hasContent !== (projection.contentParts > 0)) throw new Error('raw_projection_invalid');
  return projection;
}

function safeSubtype(runtime, subtype) {
  if (runtime === 'claude') return new Set(['user', 'assistant', 'system', 'summary', 'queue-operation', 'file-history-snapshot', 'progress', 'unknown']).has(subtype);
  const [top, nested, extra] = String(subtype).split(':');
  if (extra !== undefined || !new Set(['session_meta', 'response_item', 'event_msg', 'turn_context', 'compacted', 'ghost_snapshot', 'unknown']).has(top)) return false;
  if (nested === undefined) return true;
  return new Set(['message', 'reasoning', 'function_call', 'function_call_output', 'custom_tool_call', 'custom_tool_call_output', 'user_message', 'agent_message', 'agent_reasoning', 'token_count', 'task_started', 'task_complete', 'turn_aborted', 'context_compacted']).has(nested);
}

export function validateClientCiphertext({ actorId = null, sourceInstanceId, projection, envelope }, { allowedKeyIds = null, authorizations = null } = {}) {
  if (!SAFE_SOURCE_INSTANCE.test(String(sourceInstanceId || ''))) throw new Error('source_instance_invalid');
  validateSafeProjection(projection);
  const allowed = ['schema', 'version', 'algorithm', 'eventId', 'sessionId', 'projectionSha256', 'payloadDigest', 'sourceInstanceId', 'actorId', 'keyId', 'iv', 'tag', 'ciphertext'];
  if (!envelope || Object.keys(envelope).sort().join('\0') !== allowed.sort().join('\0')) throw new Error('raw_envelope_invalid');
  if (envelope.schema !== RAW_EVENT_CIPHERTEXT_SCHEMA || envelope.version !== RAW_EVENT_CIPHERTEXT_VERSION || envelope.algorithm !== 'aes-256-gcm') throw new Error('raw_envelope_invalid');
  if (envelope.eventId !== projection.eventId || envelope.sessionId !== projection.sessionId || envelope.projectionSha256 !== projectionDigest(projection) || envelope.sourceInstanceId !== sourceInstanceId || (actorId !== null && envelope.actorId !== actorId)) throw new Error('raw_envelope_binding_invalid');
  if (!SAFE_SOURCE_INSTANCE.test(String(envelope.sourceInstanceId || '')) || !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(String(envelope.actorId || '')) || !/^hmac-sha256:v1:[a-f0-9]{64}$/.test(String(envelope.payloadDigest || ''))) throw new Error('raw_envelope_invalid');
  if (!SAFE_KEY_ID.test(String(envelope.keyId || '')) || (allowedKeyIds && !allowedKeyIds.has(envelope.keyId))) throw new Error('raw_ingest_key_unavailable');
  const authorization = authorizations?.get(envelope.keyId);
  if (authorizations && (!authorization || !authorization.actors.has(envelope.actorId) || !authorization.sourceInstances.has(envelope.sourceInstanceId))) throw new Error('raw_ingest_key_forbidden');
  if (!canonicalBase64(envelope.iv, 12) || !canonicalBase64(envelope.tag, 16) || !canonicalBase64(envelope.ciphertext) || Buffer.from(envelope.ciphertext, 'base64').length === 0) throw new Error('raw_envelope_invalid');
  return { sourceInstanceId, projection, envelope };
}

export function ciphertextContentId(envelope) {
  return crypto.createHash('sha256').update(canonicalJson(envelope), 'utf8').digest('hex');
}

export function ciphertextPayloadDigest(envelope) {
  return envelope.payloadDigest;
}

export function decryptClientCiphertext({ actorId = null, sourceInstanceId, projection, envelope }, keyRing) {
  const normalized = keyRing?.keys instanceof Map ? keyRing : normalizeIngestKeyRing(keyRing);
  validateClientCiphertext({ actorId, sourceInstanceId, projection, envelope }, { allowedKeyIds: new Set(normalized.keys.keys()), authorizations: normalized.authorizations });
  const decipher = crypto.createDecipheriv('aes-256-gcm', normalized.keys.get(envelope.keyId), Buffer.from(envelope.iv, 'base64'));
  decipher.setAAD(rawEventAad(envelope));
  decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
  let item;
  try {
    item = JSON.parse(Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext, 'base64')), decipher.final()]).toString('utf8'));
  } catch { throw new Error('raw_envelope_authentication_failed'); }
  if (canonicalJson(item?.projection) !== canonicalJson(projection) || item?.event?.eventId !== projection.eventId || item?.event?.sessionId !== projection.sessionId) throw new Error('raw_envelope_binding_invalid');
  if (stablePayloadDigest(item, normalized.digestKey) !== envelope.payloadDigest) throw new Error('raw_payload_digest_invalid');
  if (projection.schema === 'amf.raw-event-projection/v2') {
    verifyProjectionDerivations(item, projection, normalized.digestKey);
    const logical = item?.event?.logical;
    if (!logical || typeof logical !== 'object') throw new Error('logical_message_derivation_invalid');
    const derived = deriveLogicalMessageIds({
      canonicalSenderIdentity: logical.canonicalSenderIdentity,
      senderTag: projection.contextTags.sender[0],
      conversationTag: projection.contextTags.conversation[0],
      direction: projection.direction,
      nativePlatform: logical.nativePlatform,
      nativeConversationId: logical.nativeConversationId,
      nativeMessageId: logical.nativeMessageId,
      deliveryCorrelationId: logical.deliveryCorrelationId
    }, normalized.logicalKeys);
    const allDerived = [{ keyVersion: derived.keyVersion, logicalMessageId: derived.logicalMessageId }, ...derived.aliases];
    const selected = allDerived.find(item => item.keyVersion === projection.keyVersion);
    const expectedAliases = allDerived.filter(item => item.keyVersion !== projection.keyVersion).sort((a, b) => a.keyVersion.localeCompare(b.keyVersion));
    const actualAliases = [...projection.logicalMessageAliases].sort((a, b) => a.keyVersion.localeCompare(b.keyVersion));
    if (!selected || selected.logicalMessageId !== projection.logicalMessageId || canonicalJson(expectedAliases) !== canonicalJson(actualAliases)) throw new Error('logical_message_derivation_invalid');
  }
  return item;
}
