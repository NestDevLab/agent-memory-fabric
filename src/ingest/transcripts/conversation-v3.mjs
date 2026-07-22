import {
  createConversationEvent,
  isConversationEventUtcTimestamp
} from '../../conversation-event-v3.mjs';

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function boundedNativeIdentifier(value) {
  return typeof value === 'string' && /\S/u.test(value) && Buffer.byteLength(value, 'utf8') <= 1024;
}

function firstIdentifier(...values) {
  return values.find(boundedNativeIdentifier) ?? null;
}

function normalizeText(value) {
  return value.replace(/\r\n?/g, '\n');
}

function visibleText(parts) {
  const text = parts.map(normalizeText).join('\n');
  return /\S/.test(text) ? text : null;
}

function eventPayload(identity, role, text, sourceOccurredAt, sourceSequence, occurredAt) {
  const payload = {
    eventId: identity?.eventId,
    conversationId: identity?.conversationId,
    sourceInstanceId: identity?.sourceInstanceId,
    role,
    visibleText: text,
    sourceOccurredAt,
    occurredAt,
    ordering: { sourceSequence },
    direction: role === 'user' ? 'inbound' : 'outbound',
    conversationKind: identity?.conversationKind,
    authorizationContextTags: identity?.authorizationContextTags,
    state: 'active',
    revision: 1
  };
  if (identity && Object.hasOwn(identity, 'threadId') && identity.threadId !== undefined) {
    payload.threadId = identity.threadId;
  }
  return payload;
}

export function eligibleCodexConversationPayload({
  value, identity, sourceSequence, occurredAt, sessionHint
} = {}) {
  if (!isObject(value) || value.type !== 'response_item' || !isObject(value.payload)) return null;
  const message = value.payload;
  if (message.type !== 'message' || !['user', 'assistant'].includes(message.role)) return null;
  if (!firstIdentifier(value.session_id, value.sessionId, sessionHint)) return null;
  if (!firstIdentifier(value.id, message.id, value.uuid)) return null;
  const sourceOccurredAt = value.timestamp ?? message.timestamp;
  if (!isConversationEventUtcTimestamp(sourceOccurredAt) || !Array.isArray(message.content) || message.content.length === 0) {
    return null;
  }

  const expectedPartType = message.role === 'user' ? 'input_text' : 'output_text';
  if (!message.content.every(part => isObject(part) && part.type === expectedPartType && typeof part.text === 'string')) {
    return null;
  }
  const text = visibleText(message.content.map(part => part.text));
  if (text === null) return null;
  return eventPayload(identity, message.role, text, sourceOccurredAt, sourceSequence, occurredAt);
}

export function filterCodexConversationRecord(input = {}) {
  const payload = eligibleCodexConversationPayload(input);
  return payload === null ? null : createConversationEvent(payload, input.integrity);
}

export function eligibleClaudeConversationPayload({
  value, identity, sourceSequence, occurredAt, sessionHint
} = {}) {
  if (!isObject(value) || !['user', 'assistant'].includes(value.type) || !isObject(value.message)) return null;
  const message = value.message;
  if (message.role !== value.type) return null;
  if (!firstIdentifier(value.sessionId, value.session_id, value.conversationId, sessionHint)) return null;
  if (!firstIdentifier(value.uuid, value.id, message.id)) return null;
  const sourceOccurredAt = value.timestamp ?? message.timestamp;
  if (!isConversationEventUtcTimestamp(sourceOccurredAt)) return null;

  let parts;
  if (typeof message.content === 'string') {
    parts = [message.content];
  } else if (Array.isArray(message.content) && message.content.length > 0 &&
             message.content.every(part => isObject(part) && part.type === 'text' && typeof part.text === 'string')) {
    parts = message.content.map(part => part.text);
  } else {
    return null;
  }
  const text = visibleText(parts);
  if (text === null) return null;
  return eventPayload(identity, message.role, text, sourceOccurredAt, sourceSequence, occurredAt);
}

export function filterClaudeConversationRecord(input = {}) {
  const payload = eligibleClaudeConversationPayload(input);
  return payload === null ? null : createConversationEvent(payload, input.integrity);
}
