import { strictIsoTimestamp } from './canonical.mjs';
import { buildRawEvent } from './envelope.mjs';

const EVENT_TYPES = new Set(['user', 'assistant', 'system', 'summary', 'queue-operation', 'file-history-snapshot', 'progress']);

function contentSummary(message) {
  const content = message?.content;
  if (Array.isArray(content)) {
    const types = new Set(content.map(part => String(part?.type || 'unknown')));
    const tool = [...types].some(type => /tool/.test(type));
    return { contentType: tool ? 'tool' : types.size > 1 ? 'mixed' : 'text', contentParts: content.length };
  }
  if (typeof content === 'string') return { contentType: 'text', contentParts: 1 };
  if (content && typeof content === 'object') return { contentType: 'structured', contentParts: 1 };
  return { contentType: 'none', contentParts: 0 };
}

export function claudeSessionHint(value) {
  return value?.sessionId || value?.session_id || value?.conversationId || null;
}

export function parseClaudeRecord({ value, rawBytes, lineEnding, sessionHint }) {
  const nativeSessionId = claudeSessionHint(value) || sessionHint;
  if (!nativeSessionId) throw new Error('claude_session_id_missing');
  const subtype = EVENT_TYPES.has(value?.type) ? value.type : 'unknown';
  const nativeEventId = value?.uuid || value?.id || value?.message?.id || null;
  const role = String(value?.message?.role || (subtype === 'user' || subtype === 'assistant' ? subtype : 'unknown'));
  return buildRawEvent({
    runtime: 'claude', nativeSessionId, nativeEventId, subtype,
    occurredAt: strictIsoTimestamp(value?.timestamp ?? value?.message?.timestamp),
    role, ...contentSummary(value?.message), rawBytes, lineEnding
  });
}
