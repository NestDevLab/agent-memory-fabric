import crypto from 'node:crypto';
import fs from 'node:fs';

import { canonicalJson } from './ingest/transcripts/canonical.mjs';

const SCHEMA_NAME = 'amf.conversation-event/v3';
const LOGICAL_DOMAIN = 'amf.conversation-event/v3/logical';
const INTEGRITY_DOMAIN = 'amf.conversation-event/v3/integrity';
const schema = JSON.parse(fs.readFileSync(
  new URL('../config/contracts/amf.conversation-event-v3.schema.json', import.meta.url),
  'utf8'
));
const SUPPORTED_SCHEMA_KEYWORDS = new Set([
  '$schema', '$id', '$defs', '$ref', 'title', 'description', 'type', 'additionalProperties',
  'required', 'properties', 'const', 'enum', 'pattern', 'format', 'minLength', 'maxLength',
  'minimum', 'maximum', 'minItems', 'maxItems', 'uniqueItems', 'items', 'allOf', 'if',
  'then', 'not', 'anyOf'
]);

const EVENT_FIELDS = [
  'eventId', 'conversationId', 'sourceInstanceId', 'threadId', 'role', 'visibleText',
  'sourceOccurredAt', 'occurredAt', 'ordering', 'direction', 'conversationKind',
  'authorizationContextTags', 'attachments', 'state', 'revision', 'replacesEventId',
  'tombstonesEventId', 'conflictsWithEventIds'
];

function fail(code, details) {
  const error = new Error(code);
  error.code = code;
  if (details !== undefined) error.details = details;
  throw error;
}

function assertSupportedSchema(rule) {
  for (const keyword of Object.keys(rule)) {
    if (!SUPPORTED_SCHEMA_KEYWORDS.has(keyword)) fail('conversation_event_schema_unsupported');
  }
  if (rule.format !== undefined && typeof rule.pattern !== 'string') {
    fail('conversation_event_schema_unsupported');
  }
  for (const child of Object.values(rule.$defs || {})) assertSupportedSchema(child);
  for (const child of Object.values(rule.properties || {})) assertSupportedSchema(child);
  if (rule.items) assertSupportedSchema(rule.items);
  for (const child of rule.allOf || []) assertSupportedSchema(child);
  for (const child of rule.anyOf || []) assertSupportedSchema(child);
  if (rule.not) assertSupportedSchema(rule.not);
  if (rule.if) assertSupportedSchema(rule.if);
  if (rule.then) assertSupportedSchema(rule.then);
}

assertSupportedSchema(schema);

function pointer(path, key) {
  return `${path}/${String(key).replace(/~/g, '~0').replace(/\//g, '~1')}`;
}

function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function timestampOrderKey(value) {
  const match = /^([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]{1,9}))?Z$/.exec(value);
  return `${match[1]}.${(match[2] ?? '').padEnd(9, '0')}`;
}

function typeMatches(value, expected) {
  const types = Array.isArray(expected) ? expected : [expected];
  return types.some(type =>
    (type === 'array' && Array.isArray(value)) ||
    (type === 'object' && value !== null && typeof value === 'object' && !Array.isArray(value)) ||
    (type === 'null' && value === null) ||
    (type === 'integer' && Number.isInteger(value)) ||
    (type === 'number' && typeof value === 'number' && Number.isFinite(value)) ||
    (type === 'string' && typeof value === 'string') ||
    (type === 'boolean' && typeof value === 'boolean')
  );
}

function resolveReference(reference) {
  if (!reference.startsWith('#/')) fail('conversation_event_schema_unsupported');
  return reference.slice(2).split('/').reduce((value, key) => value?.[key], schema);
}

export function isConversationEventUtcTimestamp(value) {
  if (typeof value !== 'string' ||
      !/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z$/.test(value)) {
    return false;
  }
  const millis = Date.parse(value);
  if (!Number.isFinite(millis)) return false;
  const [date, time] = value.split('T');
  const iso = new Date(millis).toISOString();
  return iso.slice(0, 10) === date && iso.slice(11, 19) === time.slice(0, 8);
}

function schemaErrors(value, rule = schema, path = '') {
  if (rule.$ref) return schemaErrors(value, resolveReference(rule.$ref), path);
  const errors = [];
  const add = (keyword, instancePath = path) => errors.push({ keyword, instancePath });

  if (rule.const !== undefined && value !== rule.const) add('const');
  if (rule.enum && !rule.enum.includes(value)) add('enum');
  if (rule.type && !typeMatches(value, rule.type)) {
    add('type');
    return errors;
  }

  if (typeof value === 'string') {
    const length = [...value].length;
    if (rule.minLength !== undefined && length < rule.minLength) add('minLength');
    if (rule.maxLength !== undefined && length > rule.maxLength) add('maxLength');
    if (rule.pattern && !new RegExp(rule.pattern).test(value)) add('pattern');
    if (rule.format === 'date-time' && !isConversationEventUtcTimestamp(value)) add('format');
  }

  if (typeof value === 'number') {
    if (rule.minimum !== undefined && value < rule.minimum) add('minimum');
    if (rule.maximum !== undefined && value > rule.maximum) add('maximum');
  }

  if (Array.isArray(value)) {
    if (rule.minItems !== undefined && value.length < rule.minItems) add('minItems');
    if (rule.maxItems !== undefined && value.length > rule.maxItems) add('maxItems');
    if (rule.uniqueItems && new Set(value.map(canonicalJson)).size !== value.length) add('uniqueItems');
    if (rule.items) {
      value.forEach((item, index) => errors.push(...schemaErrors(item, rule.items, pointer(path, index))));
    }
  }

  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    for (const key of rule.required || []) {
      if (!Object.hasOwn(value, key)) add('required');
    }
    if (rule.additionalProperties === false) {
      for (const key of Object.keys(value)) {
        if (!Object.hasOwn(rule.properties || {}, key)) add('additionalProperties', pointer(path, key));
      }
    }
    for (const [key, propertyRule] of Object.entries(rule.properties || {})) {
      if (Object.hasOwn(value, key)) {
        errors.push(...schemaErrors(value[key], propertyRule, pointer(path, key)));
      }
    }
  }

  for (const branch of rule.allOf || []) {
    const matches = schemaErrors(value, branch.if, path).length === 0;
    if (matches && branch.then) errors.push(...schemaErrors(value, branch.then, path));
  }
  if (rule.not && schemaErrors(value, rule.not, path).length === 0) add('not');
  if (rule.anyOf && !rule.anyOf.some(option => schemaErrors(value, option, path).length === 0)) add('anyOf');
  return errors;
}

function sha256(value) {
  return `sha256:${crypto.createHash('sha256').update(value, 'utf8').digest('hex')}`;
}

export function conversationEventLogicalDigest(event) {
  return sha256(canonicalJson([
    LOGICAL_DOMAIN,
    event.conversationId,
    event.threadId ?? null,
    event.role,
    event.state,
    event.visibleText ?? null,
    event.attachments ?? [],
    event.replacesEventId ?? null,
    event.tombstonesEventId ?? null,
    event.conflictsWithEventIds ?? [],
    event.revision
  ]));
}

export function conversationEventPayloadDigest(event) {
  const { integrity, ...payload } = event;
  return sha256(canonicalJson(payload));
}

function integritySignature(payloadDigest, { keyId, key, sentAt, nonce }) {
  const input = canonicalJson([INTEGRITY_DOMAIN, payloadDigest, keyId, sentAt, nonce]);
  return crypto.createHmac('sha256', key).update(input, 'utf8').digest('base64url');
}

function requireIntegrityKey(key) {
  if (!Buffer.isBuffer(key) || key.length !== 32) fail('conversation_event_integrity_key_unavailable');
  return key;
}

function authenticatedClone(event, resolveIntegrityKey) {
  const errors = schemaErrors(event);
  if (errors.length > 0) fail('conversation_event_invalid', errors);

  if (event.logicalDigest !== conversationEventLogicalDigest(event)) {
    fail('conversation_event_logical_digest_invalid');
  }
  if (event.integrity.payloadDigest !== conversationEventPayloadDigest(event)) {
    fail('conversation_event_payload_digest_invalid');
  }
  if (typeof resolveIntegrityKey !== 'function') fail('conversation_event_integrity_key_unavailable');

  let key;
  try {
    key = requireIntegrityKey(resolveIntegrityKey(event.integrity.keyId));
  } catch (error) {
    if (error?.code === 'conversation_event_integrity_key_unavailable') throw error;
    fail('conversation_event_integrity_key_unavailable');
  }
  const expected = integritySignature(event.integrity.payloadDigest, { ...event.integrity, key });
  const actualBytes = Buffer.from(event.integrity.signature, 'utf8');
  const expectedBytes = Buffer.from(expected, 'utf8');
  if (actualBytes.length !== expectedBytes.length || !crypto.timingSafeEqual(actualBytes, expectedBytes)) {
    fail('conversation_event_signature_invalid');
  }
  return JSON.parse(canonicalJson(event));
}

export function validateConversationEvent(event, { resolveIntegrityKey } = {}) {
  return authenticatedClone(event, resolveIntegrityKey);
}

export function canonicalConversationEventJson(event, options) {
  return canonicalJson(validateConversationEvent(event, options));
}

export function createConversationEvent(payload, integrity) {
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload) ||
      integrity === null || typeof integrity !== 'object' || Array.isArray(integrity)) {
    fail('conversation_event_invalid');
  }

  const event = { schema: SCHEMA_NAME };
  for (const field of EVENT_FIELDS) {
    if (Object.hasOwn(payload, field) && payload[field] !== undefined) event[field] = structuredClone(payload[field]);
  }
  event.logicalDigest = conversationEventLogicalDigest(event);
  const payloadDigest = conversationEventPayloadDigest(event);
  const key = requireIntegrityKey(integrity.key);
  event.integrity = {
    algorithm: 'hmac-sha256',
    keyId: integrity.keyId,
    sentAt: integrity.sentAt,
    nonce: integrity.nonce,
    payloadDigest,
    signature: integritySignature(payloadDigest, { ...integrity, key })
  };
  return validateConversationEvent(event, {
    resolveIntegrityKey: keyId => keyId === integrity.keyId ? key : null
  });
}

export function compareConversationEvents(left, right) {
  for (const event of [left, right]) {
    if (!isConversationEventUtcTimestamp(event?.sourceOccurredAt) ||
        !Number.isSafeInteger(event?.ordering?.sourceSequence) || event.ordering.sourceSequence < 0 ||
        typeof event?.eventId !== 'string') {
      fail('conversation_event_order_invalid');
    }
  }
  return compareStrings(timestampOrderKey(left.sourceOccurredAt), timestampOrderKey(right.sourceOccurredAt)) ||
    left.ordering.sourceSequence - right.ordering.sourceSequence ||
    compareStrings(left.eventId, right.eventId);
}
