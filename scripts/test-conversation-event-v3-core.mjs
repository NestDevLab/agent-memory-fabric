import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import test from 'node:test';

import {
  canonicalConversationEventJson,
  compareConversationEvents,
  createConversationEvent,
  validateConversationEvent
} from '../src/conversation-event-v3.mjs';
import {
  filterClaudeConversationRecord,
  filterCodexConversationRecord
} from '../src/ingest/transcripts/conversation-v3.mjs';

const fixtures = JSON.parse(fs.readFileSync(new URL('./fixtures/conversation-event-v3.conformance.json', import.meta.url), 'utf8'));
const dockerfile = fs.readFileSync(new URL('../Dockerfile', import.meta.url), 'utf8');
const dockerignore = fs.readFileSync(new URL('../.dockerignore', import.meta.url), 'utf8');
const KEY = Buffer.from(fixtures.integrityTestKey.base64, 'base64');
const TAG = 'hmac-sha256:scope-v1:1111111111111111111111111111111111111111111111111111111111111111';

function resolveKey(keyId) {
  return keyId === fixtures.integrityTestKey.keyId ? KEY : null;
}

function mergedFixture(entry) {
  const base = structuredClone(fixtures.valid[entry.base ?? 0]);
  for (const [key, value] of Object.entries(entry.payload)) {
    if (value === null) delete base[key];
    else if (key === 'integrity') base.integrity = { ...base.integrity, ...value };
    else base[key] = value;
  }
  return base;
}

function filterContext(overrides = {}) {
  return {
    identity: {
      eventId: 'cevt_filterevent0001',
      conversationId: 'ccon_filterconversation0001',
      sourceInstanceId: 'src_filtersource0001',
      conversationKind: 'session',
      authorizationContextTags: { conversation: [TAG] }
    },
    sourceSequence: 7,
    occurredAt: '2026-01-02T03:04:06Z',
    integrity: {
      keyId: fixtures.integrityTestKey.keyId,
      key: KEY,
      sentAt: '2026-01-02T03:04:07Z',
      nonce: 'synthetic_nonce_01'
    },
    ...overrides
  };
}

test('production validator accepts every valid fixture and rejects every published invalid mutation', () => {
  for (const event of fixtures.valid) {
    assert.deepEqual(validateConversationEvent(event, { resolveIntegrityKey: resolveKey }), event);
    assert.equal(canonicalConversationEventJson(event, { resolveIntegrityKey: resolveKey }),
      canonicalConversationEventJson(structuredClone(event), { resolveIntegrityKey: resolveKey }));
  }
  for (const entry of fixtures.invalid) {
    assert.throws(() => validateConversationEvent(mergedFixture(entry), { resolveIntegrityKey: resolveKey }),
      /conversation_event_/);
  }
});

test('validator authenticates logical digest, payload digest, signature, and key selection', () => {
  const fixture = fixtures.valid[0];
  for (const mutate of [
    event => { event.logicalDigest = `sha256:${'0'.repeat(64)}`; },
    event => { event.integrity.payloadDigest = `sha256:${'0'.repeat(64)}`; },
    event => { event.integrity.signature = `${event.integrity.signature.slice(0, -1)}${event.integrity.signature.endsWith('A') ? 'B' : 'A'}`; }
  ]) {
    const changed = structuredClone(fixture); mutate(changed);
    assert.throws(() => validateConversationEvent(changed, { resolveIntegrityKey: resolveKey }),
      /conversation_event_(?:logical_digest|payload_digest|signature)_invalid/);
  }
  assert.throws(() => validateConversationEvent(fixture, { resolveIntegrityKey: () => null }),
    /conversation_event_integrity_key_unavailable/);
});

test('constructor covers contract lifecycle and attachment fields without retaining extra metadata', () => {
  const created = createConversationEvent({
    eventId: 'cevt_constructed0001', conversationId: 'ccon_constructed0001',
    sourceInstanceId: 'src_constructed0001', role: 'assistant', visibleText: 'Corrected response.',
    sourceOccurredAt: '2026-01-02T03:05:05Z', occurredAt: '2026-01-02T03:05:06Z',
    ordering: { sourceSequence: 8 }, direction: 'outbound', conversationKind: 'thread',
    authorizationContextTags: { conversation: [TAG] }, state: 'replacement', revision: 2,
    replacesEventId: 'cevt_replaced000001',
    attachments: [{ attachmentId: 'catt_attachment0001', mediaType: 'image/png', byteLength: 12,
      caption: 'Visible caption.', sha256: '2'.repeat(64) }],
    raw: 'RAW_CONSTRUCTION_MARKER', localPath: '/synthetic/local/path',
    secretMetadata: 'SECRET_CONSTRUCTION_MARKER'
  }, filterContext().integrity);
  assert.deepEqual(validateConversationEvent(created, { resolveIntegrityKey: resolveKey }), created);
  assert.equal(created.logicalDigest.startsWith('sha256:'), true);
  assert.equal(created.integrity.payloadDigest.startsWith('sha256:'), true);
  assert.equal(JSON.stringify(created).includes('CONSTRUCTION_MARKER'), false);
  assert.equal(JSON.stringify(created).includes('/synthetic/local/path'), false);

  const tombstone = createConversationEvent({
    eventId: 'cevt_tombstone0009', conversationId: 'ccon_constructed0001',
    sourceInstanceId: 'src_constructed0001', role: 'user',
    sourceOccurredAt: '2026-01-02T03:06:05Z', occurredAt: '2026-01-02T03:06:06Z',
    ordering: { sourceSequence: 9 }, direction: 'inbound', conversationKind: 'thread',
    authorizationContextTags: { conversation: [TAG] }, state: 'tombstone', revision: 1,
    tombstonesEventId: created.eventId
  }, { ...filterContext().integrity, nonce: 'synthetic_nonce_02' });
  assert.equal(Object.hasOwn(tombstone, 'visibleText'), false);
  assert.equal(Object.hasOwn(tombstone, 'attachments'), false);
  assert.deepEqual(validateConversationEvent(tombstone, { resolveIntegrityKey: resolveKey }), tombstone);
});

test('Codex filter emits only deterministic visible user or assistant text', () => {
  const value = {
    type: 'response_item', id: 'native-message-secret', session_id: 'native-session-secret',
    timestamp: '2026-01-02T03:04:05Z', localPath: '/synthetic/private/path',
    payload: { type: 'message', role: 'user', content: [
      { type: 'input_text', text: 'First\r\nline', metadata: { token: 'SECRET_METADATA_MARKER' } },
      { type: 'input_text', text: 'Second\rline' }
    ], reasoning: 'REASONING_MARKER', usage: { tokens: 1 }, telemetry: 'TELEMETRY_MARKER' },
    raw: 'NATIVE_RAW_MARKER', tool: 'TOOL_MARKER'
  };
  const first = filterCodexConversationRecord({ value, ...filterContext() });
  const second = filterCodexConversationRecord({ value: structuredClone(value), ...filterContext() });
  assert.deepEqual(first, second);
  assert.equal(first.visibleText, 'First\nline\nSecond\nline');
  assert.equal(first.role, 'user'); assert.equal(first.direction, 'inbound');
  assert.equal(first.sourceOccurredAt, value.timestamp); assert.equal(first.ordering.sourceSequence, 7);
  const serialized = JSON.stringify(first);
  for (const forbidden of ['native-message-secret', 'native-session-secret', '/synthetic/private/path',
    'SECRET_METADATA_MARKER', 'REASONING_MARKER', 'TELEMETRY_MARKER', 'NATIVE_RAW_MARKER', 'TOOL_MARKER']) {
    assert.equal(serialized.includes(forbidden), false, forbidden);
  }
  assert.deepEqual(validateConversationEvent(first, { resolveIntegrityKey: resolveKey }), first);
});

test('Claude filter handles strings and all-text arrays while preserving deterministic ordering inputs', () => {
  const base = { type: 'assistant', sessionId: 'native-claude-session', uuid: 'native-claude-message',
    timestamp: '2026-01-02T03:04:05Z', message: { role: 'assistant', content: 'Visible\r\nanswer' } };
  const stringEvent = filterClaudeConversationRecord({ value: base, ...filterContext({
    identity: { ...filterContext().identity, eventId: 'cevt_claudeevent0001' }
  }) });
  assert.equal(stringEvent.visibleText, 'Visible\nanswer');
  assert.equal(stringEvent.direction, 'outbound');

  const arrayEvent = filterClaudeConversationRecord({ value: { ...base, uuid: 'native-claude-message-two',
    message: { role: 'assistant', content: [{ type: 'text', text: 'One' },
      { type: 'text', text: 'Two', metadata: { credential: 'SECRET_BLOCK_MARKER' } }] } },
  ...filterContext({ identity: { ...filterContext().identity, eventId: 'cevt_claudeevent0002' } }) });
  assert.equal(arrayEvent.visibleText, 'One\nTwo');
  assert.equal(JSON.stringify(arrayEvent).includes('SECRET_BLOCK_MARKER'), false);

  const ordered = [arrayEvent, stringEvent].sort(compareConversationEvents);
  assert.deepEqual(ordered.map(event => event.eventId), ['cevt_claudeevent0001', 'cevt_claudeevent0002']);
});

test('ordering compares UTC instants before sequence and opaque event-id tie-breaks', () => {
  const event = fixtures.valid[0];
  const atExactSecond = { ...event, sourceOccurredAt: '2026-01-02T03:04:05Z' };
  const atFraction = { ...event, sourceOccurredAt: '2026-01-02T03:04:05.000000001Z' };
  assert.equal(compareConversationEvents(atExactSecond, atFraction), -1);
  assert.equal(compareConversationEvents(atFraction, atExactSecond), 1);

  const sameFractionShort = { ...event, sourceOccurredAt: '2026-01-02T03:04:05.1Z',
    ordering: { sourceSequence: 1 } };
  const sameFractionPadded = { ...event, sourceOccurredAt: '2026-01-02T03:04:05.100Z',
    ordering: { sourceSequence: 2 } };
  assert.equal(compareConversationEvents(sameFractionShort, sameFractionPadded), -1);

  const earlierSequence = { ...atExactSecond, ordering: { sourceSequence: 1 } };
  const laterSequence = { ...atExactSecond, ordering: { sourceSequence: 2 } };
  assert.equal(compareConversationEvents(earlierSequence, laterSequence), -1);

  const lowerId = { ...earlierSequence, eventId: 'cevt_ordering0001' };
  const higherId = { ...earlierSequence, eventId: 'cevt_ordering0002' };
  assert.equal(compareConversationEvents(lowerId, higherId), -1);
});

test('Codex filter excludes every non-conversation source category and malformed eligible row', () => {
  const message = { type: 'response_item', id: 'native-message', session_id: 'native-session',
    timestamp: '2026-01-02T03:04:05Z', payload: { type: 'message', role: 'user',
      content: [{ type: 'input_text', text: 'Visible' }] } };
  const excluded = [
    { ...message, type: 'session_meta' }, { ...message, type: 'event_msg' },
    { ...message, type: 'turn_context' }, { ...message, type: 'compacted' },
    { ...message, payload: { ...message.payload, role: 'system' } },
    { ...message, payload: { ...message.payload, role: 'developer' } },
    { ...message, payload: { ...message.payload, type: 'reasoning' } },
    { ...message, payload: { ...message.payload, type: 'function_call' } },
    { ...message, payload: { ...message.payload, type: 'function_call_output' } },
    { ...message, payload: { ...message.payload, type: 'custom_tool_call' } },
    { ...message, payload: { ...message.payload, type: 'custom_tool_call_output' } },
    { ...message, payload: { ...message.payload, type: 'token_count' } },
    { ...message, payload: { ...message.payload, type: 'task_complete' } },
    { ...message, payload: { ...message.payload, type: 'user_message' } },
    { ...message, payload: { ...message.payload, content: 'structured-or-string' } },
    { ...message, payload: { ...message.payload, content: [{ type: 'output_text', text: 'wrong role part' }] } },
    { ...message, payload: { ...message.payload, content: [{ type: 'input_text', text: ' ' }] } },
    { ...message, id: null }, { ...message, id: ' \n\t' }, { ...message, id: 'x'.repeat(1025) },
    { ...message, session_id: null }, { ...message, session_id: ' \n\t' },
    { ...message, session_id: 'x'.repeat(1025) },
    { ...message, timestamp: '2026-02-30T03:04:05Z' }
  ];
  for (const value of excluded) assert.equal(filterCodexConversationRecord({ value, ...filterContext() }), null);
});

test('Claude filter excludes system, operational, mismatched, tool, structured, and malformed rows', () => {
  const message = { type: 'user', uuid: 'native-message', sessionId: 'native-session',
    timestamp: '2026-01-02T03:04:05Z', message: { role: 'user', content: 'Visible' } };
  const excluded = [
    { ...message, type: 'system', message: { ...message.message, role: 'system' } },
    { ...message, type: 'summary' }, { ...message, type: 'queue-operation' },
    { ...message, type: 'file-history-snapshot' }, { ...message, type: 'progress' },
    { ...message, message: { ...message.message, role: 'assistant' } },
    { ...message, message: { ...message.message, content: [{ type: 'tool_use', text: 'Tool' }] } },
    { ...message, message: { ...message.message, content: [{ type: 'text', text: 'Visible' }, { type: 'tool_result', text: 'Tool' }] } },
    { ...message, message: { ...message.message, content: { text: 'Structured' } } },
    { ...message, message: { ...message.message, content: ' \n\t' } },
    { ...message, uuid: null }, { ...message, uuid: ' \n\t' }, { ...message, uuid: 'x'.repeat(1025) },
    { ...message, sessionId: null }, { ...message, sessionId: ' \n\t' },
    { ...message, sessionId: 'x'.repeat(1025) },
    { ...message, timestamp: 'not-a-timestamp' }
  ];
  for (const value of excluded) assert.equal(filterClaudeConversationRecord({ value, ...filterContext() }), null);
});

test('excluded source records and extra construction metadata never serialize across either filter', () => {
  const markers = ['SYSTEM_MARKER', 'DEVELOPER_MARKER', 'TOOL_PAYLOAD_MARKER', 'REASONING_PAYLOAD_MARKER',
    'USAGE_PAYLOAD_MARKER', 'TELEMETRY_PAYLOAD_MARKER', 'RAW_ROW_MARKER', '/synthetic/local/path',
    'SECRET_METADATA_MARKER'];
  const codex = filterCodexConversationRecord({ value: {
    type: 'response_item', id: 'native-id', session_id: 'native-session', timestamp: '2026-01-02T03:04:05Z',
    payload: { type: 'message', role: 'assistant', content: [{ type: 'output_text', text: 'Safe answer',
      secret: markers.at(-1) }], developer: markers[1], reasoning: markers[3], usage: markers[4] },
    system: markers[0], tool: markers[2], telemetry: markers[5], raw: markers[6], path: markers[7]
  }, ...filterContext() });
  const claude = filterClaudeConversationRecord({ value: {
    type: 'user', uuid: 'native-id', sessionId: 'native-session', timestamp: '2026-01-02T03:04:05Z',
    message: { role: 'user', content: [{ type: 'text', text: 'Safe question', secret: markers.at(-1) }] },
    system: markers[0], developer: markers[1], tool: markers[2], reasoning: markers[3], usage: markers[4],
    telemetry: markers[5], raw: markers[6], path: markers[7]
  }, ...filterContext({ identity: { ...filterContext().identity, eventId: 'cevt_filterevent0002' } }) });
  const serialized = JSON.stringify([codex, claude]);
  for (const marker of markers) assert.equal(serialized.includes(marker), false, marker);
});

test('production image includes the exact schema required by the event core', () => {
  assert.match(dockerfile,
    /^COPY --chown=node:node config\/contracts\/amf\.conversation-event-v3\.schema\.json \.\/config\/contracts\/amf\.conversation-event-v3\.schema\.json$/m);
  assert.match(dockerignore, /^!config\/contracts\/amf\.conversation-event-v3\.schema\.json$/m);
});
