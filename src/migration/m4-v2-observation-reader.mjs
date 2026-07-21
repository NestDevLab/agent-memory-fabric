import {
  RAW_EVENT_HTTP_MAX_BODY_BYTES,
  ciphertextContentId,
  ciphertextPayloadDigest,
  decryptClientCiphertext,
  normalizeIngestKeyRing,
  validateClientCiphertext,
} from '../ingest/raw-event-contract.mjs';
import { validateProjectionV2 } from '../ingest/raw-projection-v2.mjs';
import { strictIsoTimestamp } from '../ingest/transcripts/canonical.mjs';

export const M4_V2_READER_MIN_CIPHERTEXT_BYTES = 1_024;

const V2_EVENT_ID = /^evt_[a-f0-9]{64}$/;
const V2_SESSION_ID = /^ses_[a-f0-9]{64}$/;
const LOGICAL_ID = /^lmsg_[a-f0-9]{64}$/;
const CONTENT_ID = /^[a-f0-9]{64}$/;
const PAYLOAD_DIGEST = /^hmac-sha256:v1:[a-f0-9]{64}$/;
const CATALOG_TAG = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}:[a-f0-9]{64}$/;
const MAX_VISIBLE_TEXT_CODE_POINTS = 65_536;
const MAX_VISIBLE_TEXT_BYTES = 262_144;

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

function copyCatalogRow(value) {
  const keys = [
    'eventId', 'sessionId', 'logicalMessageId', 'contentId', 'payloadDigest',
    'projection', 'ownerTag', 'sourceTag', 'createdAt',
  ];
  if (!hasExactKeys(value, keys)
    || typeof value.eventId !== 'string' || !V2_EVENT_ID.test(value.eventId)
    || typeof value.sessionId !== 'string' || !V2_SESSION_ID.test(value.sessionId)
    || typeof value.logicalMessageId !== 'string' || !LOGICAL_ID.test(value.logicalMessageId)
    || typeof value.contentId !== 'string' || !CONTENT_ID.test(value.contentId)
    || typeof value.payloadDigest !== 'string' || !PAYLOAD_DIGEST.test(value.payloadDigest)
    || typeof value.ownerTag !== 'string' || !CATALOG_TAG.test(value.ownerTag)
    || typeof value.sourceTag !== 'string' || !CATALOG_TAG.test(value.sourceTag)
    || typeof value.createdAt !== 'string' || strictIsoTimestamp(value.createdAt) !== value.createdAt) {
    fail('m4_v2_reader_catalog_invalid');
  }
  let projection;
  try {
    projection = validateProjectionV2(value.projection);
  } catch {
    fail('m4_v2_reader_catalog_invalid');
  }
  const signedLogicalIds = new Set([
    projection.logicalMessageId,
    ...projection.logicalMessageAliases.map(alias => alias.logicalMessageId),
  ]);
  if (projection.eventId !== value.eventId
    || projection.sessionId !== value.sessionId
    || !signedLogicalIds.has(value.logicalMessageId)) {
    fail('m4_v2_reader_catalog_invalid');
  }
  return {
    eventId: value.eventId,
    sessionId: value.sessionId,
    logicalMessageId: value.logicalMessageId,
    contentId: value.contentId,
    payloadDigest: value.payloadDigest,
    transportProjection: structuredClone(projection),
    ownerTag: value.ownerTag,
    sourceTag: value.sourceTag,
    createdAt: value.createdAt,
  };
}

function ciphertextBytes(envelope, maxCiphertextBytes) {
  if (!isPlainObject(envelope) || typeof envelope.ciphertext !== 'string') {
    fail('m4_v2_reader_envelope_invalid');
  }
  const encoded = envelope.ciphertext;
  const maximumEncodedLength = 4 * Math.ceil(maxCiphertextBytes / 3);
  if (encoded.length === 0 || encoded.length > maximumEncodedLength) {
    fail('m4_v2_reader_ciphertext_bounds_invalid');
  }
  const padding = encoded.endsWith('==') ? 2 : encoded.endsWith('=') ? 1 : 0;
  const decodedLength = (encoded.length / 4) * 3 - padding;
  if (!Number.isSafeInteger(decodedLength) || decodedLength < 1 || decodedLength > maxCiphertextBytes) {
    fail('m4_v2_reader_ciphertext_bounds_invalid');
  }
  return decodedLength;
}

function validateMaxCiphertextBytes(value) {
  if (!Number.isSafeInteger(value)
    || value < M4_V2_READER_MIN_CIPHERTEXT_BYTES
    || value > RAW_EVENT_HTTP_MAX_BODY_BYTES) {
    fail('m4_v2_reader_request_invalid');
  }
  return value;
}

function verifyNormalizedText(normalized, projection) {
  if (!hasExactKeys(normalized, ['role', 'contentType', 'value'])
    || typeof normalized.role !== 'string'
    || typeof normalized.contentType !== 'string'
    || normalized.role !== projection.role
    || normalized.contentType !== projection.contentType) {
    fail('m4_v2_reader_normalized_invalid');
  }
  if (typeof normalized.value === 'string') {
    if (projection.contentParts !== 1) fail('m4_v2_reader_normalized_invalid');
    return normalized.value;
  }
  if (!Array.isArray(normalized.value)
    || normalized.value.length < 1
    || normalized.value.length > 100
    || projection.contentParts !== normalized.value.length) {
    fail('m4_v2_reader_normalized_invalid');
  }
  const parts = normalized.value.map(part => {
    if (!hasExactKeys(part, ['type', 'text'])
      || !['text', 'input_text', 'output_text'].includes(part.type)
      || typeof part.text !== 'string') {
      fail('m4_v2_reader_normalized_invalid');
    }
    return part.text;
  });
  return parts.join('\n');
}

function boundedVisibleText(value) {
  if (typeof value !== 'string'
    || !/\S/u.test(value)
    || [...value].length > MAX_VISIBLE_TEXT_CODE_POINTS
    || Buffer.byteLength(value, 'utf8') > MAX_VISIBLE_TEXT_BYTES) {
    fail('m4_v2_reader_visible_text_invalid');
  }
  return value;
}

function visibleTextFromDecrypted(item, projection) {
  if (projection.authoritativeDeletion) return null;
  const conversation = (projection.role === 'user' && projection.direction === 'inbound')
    || (projection.role === 'assistant' && projection.direction === 'outbound');
  if (!conversation
    || !['dm', 'group', 'channel', 'thread', 'session'].includes(projection.conversationKind)
    || projection.contentType !== 'text') {
    return null;
  }
  return boundedVisibleText(verifyNormalizedText(item?.event?.normalized, projection));
}

function preflightEnvelope(envelope, row, ingestKeys) {
  let normalized;
  try {
    normalized = normalizeIngestKeyRing(ingestKeys);
    validateClientCiphertext({
      actorId: envelope?.actorId,
      sourceInstanceId: envelope?.sourceInstanceId,
      projection: row.transportProjection,
      envelope,
    }, {
      allowedKeyIds: new Set(normalized.keys.keys()),
      authorizations: normalized.authorizations,
    });
  } catch {
    fail('m4_v2_reader_envelope_or_key_invalid');
  }
  return normalized;
}

function canonicalizeProjectorProjection(transportProjection, logicalMessageId) {
  const signedEntries = [
    { keyVersion: transportProjection.keyVersion, logicalMessageId: transportProjection.logicalMessageId },
    ...transportProjection.logicalMessageAliases.map(alias => ({ ...alias })),
  ];
  const selectedIndex = signedEntries.findIndex(entry => entry.logicalMessageId === logicalMessageId);
  if (selectedIndex < 0) fail('m4_v2_reader_catalog_invalid');
  const selected = signedEntries[selectedIndex];
  const projectorProjection = structuredClone(transportProjection);
  projectorProjection.keyVersion = selected.keyVersion;
  projectorProjection.logicalMessageId = selected.logicalMessageId;
  projectorProjection.logicalMessageAliases = signedEntries
    .filter((_, index) => index !== selectedIndex)
    .sort((left, right) => left.keyVersion.localeCompare(right.keyVersion)
      || left.logicalMessageId.localeCompare(right.logicalMessageId));
  try {
    return validateProjectionV2(projectorProjection);
  } catch {
    fail('m4_v2_reader_catalog_invalid');
  }
}

async function verifyBinding(verifyCatalogBinding, envelope, row) {
  if (typeof verifyCatalogBinding !== 'function') fail('m4_v2_reader_binding_verifier_required');
  let result;
  try {
    result = await verifyCatalogBinding({
      ownerTag: row.ownerTag,
      sourceTag: row.sourceTag,
      actorId: envelope.actorId,
      sourceInstanceId: envelope.sourceInstanceId,
    });
  } catch {
    fail('m4_v2_reader_binding_verification_failed');
  }
  if (!hasExactKeys(result, ['owner', 'source']) || result.owner !== true || result.source !== true) {
    fail('m4_v2_reader_binding_verification_failed');
  }
}

async function recordDecryptAudit(auditDecrypt, row, size) {
  if (typeof auditDecrypt !== 'function') fail('m4_v2_reader_audit_required');
  let acknowledgement;
  try {
    acknowledgement = await auditDecrypt({
      eventId: row.eventId,
      sessionId: row.sessionId,
      contentId: row.contentId,
      ciphertextBytes: size,
      view: 'normalized-migration',
    });
  } catch {
    fail('m4_v2_reader_audit_unavailable');
  }
  if (!hasExactKeys(acknowledgement, ['recorded', 'eventId', 'contentId'])
    || acknowledgement.recorded !== true
    || acknowledgement.eventId !== row.eventId
    || acknowledgement.contentId !== row.contentId) {
    fail('m4_v2_reader_audit_unavailable');
  }
}

export async function readM4V2Observation({
  catalogRow,
  envelope,
  ingestKeys,
  migrationSequence,
  verifyCatalogBinding,
  auditDecrypt,
  maxCiphertextBytes = RAW_EVENT_HTTP_MAX_BODY_BYTES,
} = {}) {
  const row = copyCatalogRow(catalogRow);
  if (!Number.isSafeInteger(migrationSequence) || migrationSequence < 0) {
    fail('m4_v2_reader_request_invalid');
  }
  const maxBytes = validateMaxCiphertextBytes(maxCiphertextBytes);
  const size = ciphertextBytes(envelope, maxBytes);
  const normalizedKeys = preflightEnvelope(envelope, row, ingestKeys);
  let contentId;
  let payloadDigest;
  try {
    contentId = ciphertextContentId(envelope);
    payloadDigest = ciphertextPayloadDigest(envelope);
  } catch {
    fail('m4_v2_reader_envelope_invalid');
  }
  if (contentId !== row.contentId || payloadDigest !== row.payloadDigest) {
    fail('m4_v2_reader_catalog_binding_invalid');
  }
  await verifyBinding(verifyCatalogBinding, envelope, row);
  await recordDecryptAudit(auditDecrypt, row, size);

  let decrypted;
  try {
    decrypted = decryptClientCiphertext({
      actorId: envelope.actorId,
      sourceInstanceId: envelope.sourceInstanceId,
      projection: row.transportProjection,
      envelope,
    }, normalizedKeys);
  } catch {
    fail('m4_v2_reader_decrypt_invalid');
  }
  const visibleText = visibleTextFromDecrypted(decrypted, row.transportProjection);
  const projectorProjection = canonicalizeProjectorProjection(
    row.transportProjection,
    row.logicalMessageId,
  );
  return {
    eventId: row.eventId,
    sessionId: row.sessionId,
    sourceTag: row.sourceTag,
    migrationSequence,
    projection: projectorProjection,
    visibleText,
  };
}
