import { strictIsoTimestamp } from './canonical.mjs';
import { buildRawEvent } from './envelope.mjs';

const TOP_LEVEL_TYPES = new Set(['session_meta', 'response_item', 'event_msg', 'turn_context', 'compacted', 'ghost_snapshot']);
const PAYLOAD_TYPES = new Set([
  'message', 'reasoning', 'function_call', 'function_call_output', 'custom_tool_call', 'custom_tool_call_output',
  'user_message', 'agent_message', 'agent_reasoning', 'token_count', 'task_started', 'task_complete',
  'turn_aborted', 'context_compacted'
]);

function safeSubtype(value, payload) {
  const top = TOP_LEVEL_TYPES.has(value?.type) ? value.type : 'unknown';
  const nested = PAYLOAD_TYPES.has(payload?.type) ? payload.type : null;
  return nested ? `${top}:${nested}` : top;
}

function contentSummary(payload) {
  const content = payload?.content;
  if (Array.isArray(content)) {
    const types = new Set(content.map(part => String(part?.type || 'unknown')));
    const contentType = [...types].some(type => /tool|function/.test(type)) ? 'tool' : types.size > 1 ? 'mixed' : 'text';
    return { contentType, contentParts: content.length };
  }
  if (typeof payload?.message === 'string' || typeof content === 'string') return { contentType: 'text', contentParts: 1 };
  if (content && typeof content === 'object') return { contentType: 'structured', contentParts: 1 };
  return { contentType: 'none', contentParts: 0 };
}

export function codexSessionHint(value) {
  if (value?.type === 'session_meta') return value?.payload?.id || value?.session_id || value?.sessionId || null;
  return value?.session_id || value?.sessionId || null;
}

export function parseCodexRecord({ value, rawBytes, lineEnding, sessionHint }) {
  const payload = value?.payload && typeof value.payload === 'object' ? value.payload : {};
  const nativeSessionId = codexSessionHint(value) || sessionHint;
  if (!nativeSessionId) throw new Error('codex_session_id_missing');
  const subtype = safeSubtype(value, payload);
  const nativeEventId = value?.id || payload?.id || value?.uuid || null;
  const role = String(payload?.role || (
    payload?.type === 'user_message' ? 'user' : payload?.type === 'agent_message' ? 'assistant' : 'unknown'
  ));
  return buildRawEvent({
    runtime: 'codex', nativeSessionId, nativeEventId, subtype,
    occurredAt: strictIsoTimestamp(value?.timestamp ?? payload?.timestamp),
    role, ...contentSummary(payload), rawBytes, lineEnding
  });
}
