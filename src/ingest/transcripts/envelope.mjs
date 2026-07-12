import { stableEventId, stableSessionId } from './identity.mjs';

const SAFE_ROLES = new Set(['user', 'assistant', 'system', 'tool', 'unknown']);
const SAFE_CONTENT_TYPES = new Set(['text', 'structured', 'tool', 'mixed', 'none', 'unknown']);

export function buildRawEvent({ runtime, nativeSessionId, nativeEventId = null, subtype, occurredAt = null, role = 'unknown', contentType = 'unknown', contentParts = 0, rawBytes, lineEnding }) {
  if (!Buffer.isBuffer(rawBytes)) throw new Error('raw_event_bytes_required');
  const eventId = stableEventId({ runtime, nativeSessionId, nativeEventId, subtype, rawBytes });
  const sessionId = stableSessionId({ runtime, nativeSessionId });
  const safeRole = SAFE_ROLES.has(role) ? role : 'unknown';
  const safeContentType = SAFE_CONTENT_TYPES.has(contentType) ? contentType : 'unknown';
  return {
    event: {
      schema: 'amf.raw-event/v1',
      eventId,
      sessionId,
      source: { runtime, nativeSessionId, nativeEventId, subtype },
      occurredAt,
      raw: { encoding: 'base64', line: rawBytes.toString('base64'), lineEnding }
    },
    projection: Object.freeze({
      schema: 'amf.raw-event-projection/v1',
      eventId,
      sessionId,
      runtime,
      subtype,
      occurredAt,
      role: safeRole,
      contentType: safeContentType,
      contentParts: Number.isSafeInteger(contentParts) && contentParts >= 0 ? contentParts : 0,
      hasContent: contentParts > 0
    })
  };
}
