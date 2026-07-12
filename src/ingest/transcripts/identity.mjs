import { sha256Id } from './canonical.mjs';

function required(value, name) {
  const text = String(value ?? '');
  if (!text) throw new Error(`${name}_required`);
  return text;
}

export function stableSessionId({ runtime, nativeSessionId }) {
  return `ses_${sha256Id('amf-session-v1', required(runtime, 'runtime'), required(nativeSessionId, 'native_session_id'))}`;
}

export function stableEventId({ runtime, nativeSessionId, nativeEventId, subtype, rawBytes }) {
  const nativeOrFallback = nativeEventId
    ? `native:${nativeEventId}`
    : `raw:${sha256Id('amf-event-raw-v1', Buffer.from(rawBytes).toString('base64'))}`;
  return `evt_${sha256Id(
    'amf-event-v1',
    required(runtime, 'runtime'),
    required(nativeSessionId, 'native_session_id'),
    required(subtype, 'event_subtype'),
    nativeOrFallback
  )}`;
}
