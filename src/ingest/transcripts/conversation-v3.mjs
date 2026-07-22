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

function lifecyclePayload(payload, lifecycle, resolved) {
  if (!isObject(payload) || !isObject(lifecycle) || !isObject(resolved)) return null;
  const change = lifecycle.change;
  const prior = resolved.priorEventId;
  if (change === 'new') {
    if (prior !== null || !(lifecycle.nativeRevision === null || lifecycle.nativeRevision === 0 || lifecycle.nativeRevision === 1)) return null;
    return { ...payload, state: 'active', revision: 1 };
  }
  if (change === 'changed') {
    if (typeof prior !== 'string' || !Number.isSafeInteger(lifecycle.nativeRevision) || lifecycle.nativeRevision < 2) return null;
    return { ...payload, state: 'edited', revision: lifecycle.nativeRevision, replacesEventId: prior };
  }
  if (change === 'deleted') {
    if (typeof prior !== 'string' || !Number.isSafeInteger(lifecycle.nativeRevision) || lifecycle.nativeRevision < 2) return null;
    const { visibleText, attachments, ...tombstone } = payload;
    return { ...tombstone, state: 'tombstone', revision: lifecycle.nativeRevision, tombstonesEventId: prior };
  }
  return null;
}

function hermesBasePayload({ value, identity, sourceSequence, occurredAt, sessionHint } = {}) {
  if (!isObject(value) || !['user', 'assistant'].includes(value.role)
    || !firstIdentifier(value.session_id, sessionHint) || !firstIdentifier(value.revisionEventId, value.stableNativeMessageId)
    || !isConversationEventUtcTimestamp(value.timestamp)) return null;
  if (!['message', 'message.deleted'].includes(value.subtype)) return null;
  if (value.authoritativeDeletion === true) {
    if (value.subtype !== 'message.deleted') return null;
    return eventPayload(identity, value.role, null, value.timestamp, sourceSequence, occurredAt);
  }
  if (value.subtype !== 'message' || typeof value.content !== 'string') return null;
  const text = visibleText([value.content]);
  return text === null ? null : eventPayload(identity, value.role, text, value.timestamp, sourceSequence, occurredAt);
}

function lifecycleFromEligible(eligible, options) {
  const payload = eligible(options);
  if (payload === null) return null;
  return lifecyclePayload(payload, options.lifecycle, options.resolved);
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

export function eligibleCodexConversationLifecyclePayload(input = {}) {
  return lifecycleFromEligible(eligibleCodexConversationPayload, input);
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

export function eligibleClaudeConversationLifecyclePayload(input = {}) {
  return lifecycleFromEligible(eligibleClaudeConversationPayload, input);
}

export function eligibleOpenClawConversationPayload({
  value, identity, sourceSequence, occurredAt, sessionHint
} = {}) {
  if (!isObject(value) || value.type !== 'message' || !isObject(value.message)) return null;
  const message = value.message;
  if (!['user', 'assistant'].includes(message.role)) return null;
  if (!firstIdentifier(value.sessionKey, value.session_key, value.sessionId, value.session_id, sessionHint)) return null;
  if (!firstIdentifier(value.id, value.uuid, value.messageId, value.message_id, message.id)) return null;
  const sourceOccurredAt = value.timestamp ?? value.createdAt ?? message.timestamp;
  if (!isConversationEventUtcTimestamp(sourceOccurredAt)) return null;

  let parts;
  if (typeof message.content === 'string') {
    parts = [message.content];
  } else if (Array.isArray(message.content) && message.content.length > 0
             && message.content.every(part => isObject(part) && part.type === 'text'
               && typeof part.text === 'string')) {
    parts = message.content.map(part => part.text);
  } else {
    return null;
  }
  const text = visibleText(parts);
  if (text === null) return null;
  return eventPayload(identity, message.role, text, sourceOccurredAt, sourceSequence, occurredAt);
}

export function filterOpenClawConversationRecord(input = {}) {
  const payload = eligibleOpenClawConversationPayload(input);
  return payload === null ? null : createConversationEvent(payload, input.integrity);
}

export function eligibleOpenClawConversationLifecyclePayload(input = {}) {
  return lifecycleFromEligible(eligibleOpenClawConversationPayload, input);
}

export function eligibleHermesConversationPayload({ value, identity, sourceSequence, occurredAt, sessionHint } = {}) {
  const base = hermesBasePayload({ value, identity, sourceSequence, occurredAt, sessionHint });
  return base?.visibleText === null ? null : base;
}

export function eligibleHermesConversationLifecyclePayload(input = {}) {
  const base = hermesBasePayload(input);
  if (base === null) return null;
  return lifecyclePayload(base, input.lifecycle, input.resolved);
}
