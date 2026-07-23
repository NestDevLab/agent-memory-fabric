import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  RAW_EVENT_HTTP_MAX_BODY_BYTES,
  ciphertextContentId,
  normalizeIngestKeyRing,
  normalizedObservationDigest,
} from '../src/ingest/raw-event-contract.mjs';
import { EncryptedOutbox } from '../src/ingest/outbox.mjs';
import { validateConversationEvent } from '../src/conversation-event-v3.mjs';
import {
  OBSERVATION_NORMALIZATION_VERSION,
  deriveEventIdV2,
  deriveLogicalMessageIds,
  deriveSessionIdV2,
  opaqueContextTag,
} from '../src/ingest/raw-projection-v2.mjs';
import { projectM4V2LogicalGroup } from '../src/migration/m4-v2-conversation-projector.mjs';
import { readM4V2CatalogObservation, readM4V2Observation } from '../src/migration/m4-v2-observation-reader.mjs';

const INGEST_KEY = Buffer.alloc(32, 7).toString('base64');
const LOGICAL_KEY = Buffer.alloc(32, 8).toString('base64');
const LOGICAL_KEY_ROTATED = Buffer.alloc(32, 10).toString('base64');
const TAG_KEY = Buffer.alloc(32, 9).toString('base64');
const KEY_RING = {
  keys: { ingest: INGEST_KEY },
  digestKey: INGEST_KEY,
  authorizations: { ingest: { actors: ['synthetic-actor', 'synthetic-other'], sourceInstances: ['synthetic-source'] } },
  logicalMessageKeys: { currentKeyVersion: 'logical-k1', keys: { 'logical-k1': LOGICAL_KEY } },
};
const ROTATING_KEY_RING = {
  ...KEY_RING,
  logicalMessageKeys: {
    currentKeyVersion: 'logical-k1',
    keys: { 'logical-k1': LOGICAL_KEY, 'logical-k2': LOGICAL_KEY_ROTATED },
  },
};
const DIGEST_KEY = normalizeIngestKeyRing(KEY_RING).digestKey;
const CATALOG_OWNER_TAG = `catalog-k1:${'a'.repeat(64)}`;
const CATALOG_SOURCE_TAG = `catalog-k1:${'b'.repeat(64)}`;

function tag(namespace, value) {
  return opaqueContextTag(namespace, value, TAG_KEY, 'routing-k1');
}

function createItem({
  suffix = 'one',
  role = 'user',
  direction = 'inbound',
  contentType = 'text',
  conversationKind = 'dm',
  value = 'synthetic normalized text',
  authoritativeDeletion = false,
  contentParts = null,
  logicalKeys = KEY_RING.logicalMessageKeys,
  sourceKind = 'codex',
} = {}) {
  const senderTag = tag('sender', 'synthetic-sender');
  const conversationTag = tag('conversation', 'synthetic-conversation');
  const logical = {
    canonicalSenderIdentity: 'synthetic-sender',
    senderTag,
    conversationTag,
    direction,
    nativePlatform: 'synthetic-platform',
    nativeConversationId: 'synthetic-conversation',
    nativeMessageId: `synthetic-message-${suffix}`,
  };
  const derivedLogical = deriveLogicalMessageIds(logical, logicalKeys);
  const rawBytes = Buffer.from(`synthetic-raw-${suffix}`, 'utf8');
  const eventId = deriveEventIdV2({
    sourceKind,
    observationClass: 'native',
    rawBytes,
  });
  const sessionId = deriveSessionIdV2({ sourceKind, conversationTag });
  const normalized = {
    role,
    contentType,
    value: authoritativeDeletion ? null : value,
  };
  const event = {
    schema: 'amf.raw-event/v2',
    eventId,
    sessionId,
    occurredAt: '2026-07-21T12:00:00.123456789Z',
    source: { runtime: sourceKind, subtype: authoritativeDeletion ? 'message.deleted' : 'message' },
    logical,
    normalized,
    raw: { encoding: 'base64', line: rawBytes.toString('base64'), lineEnding: 'lf' },
  };
  const actualParts = contentParts ?? (Array.isArray(normalized.value) ? normalized.value.length : authoritativeDeletion ? 0 : 1);
  const projection = {
    schema: 'amf.raw-event-projection/v2',
    eventId,
    sessionId,
    logicalMessageId: derivedLogical.logicalMessageId,
    logicalMessageAliases: derivedLogical.aliases,
    derivationVersion: 'amf-logical-message/v1',
    keyVersion: derivedLogical.keyVersion,
    sourceKind,
    observationClass: 'native',
    direction,
    conversationKind,
    contextTags: {
      actor: [tag('actor', 'synthetic-actor')],
      sender: [senderTag],
      conversation: [conversationTag],
      room: [tag('room', 'synthetic-room')],
    },
    subtype: authoritativeDeletion ? 'message.deleted' : 'message',
    occurredAt: event.occurredAt,
    editedAt: null,
    nativeRevision: 1,
    sourceSequence: 1,
    authoritativeDeletion,
    role,
    contentType,
    contentParts: actualParts,
    hasContent: actualParts > 0,
    normalizationVersion: OBSERVATION_NORMALIZATION_VERSION,
    normalizedPayloadDigest: normalizedObservationDigest({ event }, DIGEST_KEY),
  };
  return { event, projection };
}

function encrypt(item) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-m4-reader-'));
  try {
    return new EncryptedOutbox({
      rootPath: root,
      encryptionKey: INGEST_KEY,
      digestKey: INGEST_KEY,
      sourceInstanceId: 'synthetic-source',
      actorId: 'synthetic-actor',
      keyId: 'ingest',
    }).encrypt(item);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

function rowFor(item, envelope) {
  return {
    eventId: item.event.eventId,
    sessionId: item.event.sessionId,
    logicalMessageId: item.projection.logicalMessageId,
    contentId: ciphertextContentId(envelope),
    payloadDigest: envelope.payloadDigest,
    projection: structuredClone(item.projection),
    ownerTag: CATALOG_OWNER_TAG,
    sourceTag: CATALOG_SOURCE_TAG,
    createdAt: '2026-07-21T12:00:01Z',
  };
}

function dependencies(overrides = {}) {
  const calls = { binding: [], audit: [] };
  return {
    calls,
    verifyCatalogBinding: async input => {
      calls.binding.push(structuredClone(input));
      return { owner: true, source: true };
    },
    auditDecrypt: async input => {
      calls.audit.push(structuredClone(input));
      return { recorded: true, eventId: input.eventId, contentId: input.contentId };
    },
    ...overrides,
  };
}

async function read(itemOptions = {}, overrides = {}) {
  const item = createItem(itemOptions);
  const envelope = encrypt(item);
  const row = rowFor(item, envelope);
  const injected = dependencies(overrides);
  const result = await readM4V2Observation({
    catalogRow: row,
    envelope,
    ingestKeys: KEY_RING,
    migrationSequence: 7,
    verifyCatalogBinding: injected.verifyCatalogBinding,
    auditDecrypt: injected.auditDecrypt,
    ...overrides.request,
  });
  return { item, envelope, row, injected, result };
}

function assertCode(action, code) {
  return assert.rejects(action, error => error?.code === code && error.message === code);
}

function assertNoLeak(error, literal) {
  assert.equal(JSON.stringify({ code: error.code, message: error.message }).includes(literal), false);
}

test('production envelope decrypts to an exact projector-compatible user wrapper', async () => {
  const { item, result, injected } = await read();
  assert.deepEqual(Object.keys(result).sort(), [
    'eventId', 'migrationSequence', 'projection', 'sessionId', 'sourceTag', 'visibleText',
  ]);
  assert.equal(result.visibleText, 'synthetic normalized text');
  assert.deepEqual(injected.calls.binding, [{
    ownerTag: CATALOG_OWNER_TAG,
    sourceTag: CATALOG_SOURCE_TAG,
    actorId: 'synthetic-actor',
    sourceInstanceId: 'synthetic-source',
  }]);
  assert.deepEqual(Object.keys(injected.calls.audit[0]).sort(), [
    'ciphertextBytes', 'contentId', 'eventId', 'sessionId', 'view',
  ]);
  for (const callbackInput of [...injected.calls.binding, ...injected.calls.audit]) {
    assert.equal(JSON.stringify(callbackInput).includes(item.event.raw.line), false);
    assert.equal(JSON.stringify(callbackInput).includes('synthetic normalized text'), false);
  }
  const logical = {
    logicalMessageId: item.projection.logicalMessageId,
    preferredObservationId: item.event.eventId,
    payloadConflict: false,
    tombstoned: false,
    selectionVersion: 'amf-observation-selection/v1',
    eventIds: [item.event.eventId],
  };
  const projected = await projectM4V2LogicalGroup({
    logical,
    observations: [result],
    integrityFor: () => ({
      sentAt: '2026-07-21T12:00:02Z',
      keyId: 'test-k1',
      key: Buffer.alloc(32, 5),
      nonce: 'n'.repeat(16),
    }),
  });
  assert.equal(projected.outcome, 'projected');
  assert.equal(projected.events.length, 1);
  assert.equal(validateConversationEvent(projected.events[0], {
    resolveIntegrityKey: keyId => keyId === 'test-k1' ? Buffer.alloc(32, 5) : null,
  }).eventId, projected.events[0].eventId);
  assert.equal(JSON.stringify(result).includes(item.event.raw.line), false);
});

test('assistant, authoritative deletion, and non-conversation rows are deterministically stripped', async () => {
  assert.equal((await read({ role: 'assistant', direction: 'outbound', suffix: 'assistant' })).result.visibleText, 'synthetic normalized text');
  assert.equal((await read({ authoritativeDeletion: true, contentType: 'none', suffix: 'deletion' })).result.visibleText, null);
  assert.equal((await read({ role: 'tool', contentType: 'tool', value: { structured: true }, suffix: 'tool' })).result.visibleText, null);
  assert.equal((await read({ role: 'system', contentType: 'structured', value: { structured: true }, suffix: 'system' })).result.visibleText, null);
});

test('Claude thinking-only assistant content is private reasoning and never becomes visible text', async () => {
  const thinking = [{
    signature: 'synthetic-signature',
    thinking: 'SYNTHETIC_PRIVATE_REASONING',
    type: 'thinking',
  }];
  const result = await read({
    sourceKind: 'claude',
    role: 'assistant',
    direction: 'outbound',
    value: thinking,
    suffix: 'claude-thinking',
  });
  assert.equal(result.result.visibleText, null);
  assert.equal(JSON.stringify(result.result).includes('SYNTHETIC_PRIVATE_REASONING'), false);

  for (const value of [
    [{ type: 'thinking', thinking: 'private', signature: 'signature', extra: true }],
    [{ type: 'thinking', thinking: 'private' }],
    [{ type: 'text', thinking: 'private', signature: 'signature' }],
  ]) {
    await assertCode(() => read({
      sourceKind: 'claude',
      role: 'assistant',
      direction: 'outbound',
      value,
      suffix: crypto.randomUUID(),
    }), 'm4_v2_reader_normalized_invalid');
  }
});

test('catalog-only observations accept metadata but require decrypt for potential conversation rows', async () => {
  const metadata = createItem({
    role: 'system',
    direction: 'internal',
    contentType: 'structured',
    value: { ignored: true },
    suffix: 'catalog-metadata',
  });
  const metadataEnvelope = encrypt(metadata);
  const observation = readM4V2CatalogObservation({
    catalogRow: rowFor(metadata, metadataEnvelope),
    migrationSequence: 3,
  });
  assert.equal(observation.visibleText, null);
  assert.equal(observation.migrationSequence, 3);

  const conversation = createItem({ suffix: 'catalog-conversation' });
  const conversationEnvelope = encrypt(conversation);
  assert.throws(() => readM4V2CatalogObservation({
    catalogRow: rowFor(conversation, conversationEnvelope),
    migrationSequence: 4,
  }), { code: 'm4_v2_reader_decrypt_required' });
});

test('preflight rejects malformed envelopes before callbacks and valid output is mutation isolated', async () => {
  const item = createItem({ suffix: 'preflight' });
  const envelope = encrypt(item);
  const row = rowFor(item, envelope);
  const injected = dependencies();
  const noncanonical = { ...envelope, ciphertext: `!${envelope.ciphertext.slice(1)}` };
  await assertCode(() => readM4V2Observation({
    catalogRow: row,
    envelope: noncanonical,
    ingestKeys: KEY_RING,
    migrationSequence: 1,
    verifyCatalogBinding: injected.verifyCatalogBinding,
    auditDecrypt: injected.auditDecrypt,
  }), 'm4_v2_reader_envelope_or_key_invalid');
  assert.deepEqual(injected.calls, { binding: [], audit: [] });

  const huge = { ...envelope, ciphertext: 'A'.repeat((RAW_EVENT_HTTP_MAX_BODY_BYTES * 2) + 4) };
  await assertCode(() => readM4V2Observation({
    catalogRow: row,
    envelope: huge,
    ingestKeys: KEY_RING,
    migrationSequence: 1,
    verifyCatalogBinding: injected.verifyCatalogBinding,
    auditDecrypt: injected.auditDecrypt,
  }), 'm4_v2_reader_ciphertext_bounds_invalid');
  assert.deepEqual(injected.calls, { binding: [], audit: [] });

  const result = await readM4V2Observation({
    catalogRow: row,
    envelope,
    ingestKeys: KEY_RING,
    migrationSequence: 1,
    verifyCatalogBinding: injected.verifyCatalogBinding,
    auditDecrypt: injected.auditDecrypt,
  });
  row.projection.contextTags.actor[0] = tag('actor', 'mutated');
  assert.notEqual(result.projection.contextTags.actor[0], row.projection.contextTags.actor[0]);
});

test('binding, audit, decrypt, bounds, and eligible text failures are fixed and content-free', async () => {
  const item = createItem({ suffix: 'failures' });
  const envelope = encrypt(item);
  const row = rowFor(item, envelope);
  const literal = item.event.raw.line;
  const base = {
    catalogRow: row,
    envelope,
    ingestKeys: KEY_RING,
    migrationSequence: 1,
  };
  let auditCalls = 0;
  await assertCode(() => readM4V2Observation({
    ...base,
    verifyCatalogBinding: async () => { throw new Error(`secret-${literal}`); },
    auditDecrypt: async () => { auditCalls += 1; return {}; },
  }), 'm4_v2_reader_binding_verification_failed');
  assert.equal(auditCalls, 0);

  await assertCode(() => readM4V2Observation({
    ...base,
    verifyCatalogBinding: async () => ({ owner: true, source: true }),
    auditDecrypt: async () => ({ recorded: false, eventId: row.eventId, contentId: row.contentId }),
  }), 'm4_v2_reader_audit_unavailable');

  await assertCode(() => readM4V2Observation({
    ...base,
    ingestKeys: { ...KEY_RING, keys: { ingest: Buffer.alloc(32, 3).toString('base64') } },
    verifyCatalogBinding: async () => ({ owner: true, source: true }),
    auditDecrypt: async () => ({ recorded: true, eventId: row.eventId, contentId: row.contentId }),
  }), 'm4_v2_reader_decrypt_invalid');

  await assertCode(() => readM4V2Observation({
    ...base,
    maxCiphertextBytes: RAW_EVENT_HTTP_MAX_BODY_BYTES + 1,
    verifyCatalogBinding: async () => ({ owner: true, source: true }),
    auditDecrypt: async () => ({ recorded: true, eventId: row.eventId, contentId: row.contentId }),
  }), 'm4_v2_reader_request_invalid');

  const blankItem = createItem({ suffix: 'blank', value: '  ' });
  const blankEnvelope = encrypt(blankItem);
  await assertCode(() => readM4V2Observation({
    catalogRow: rowFor(blankItem, blankEnvelope),
    envelope: blankEnvelope,
    ingestKeys: KEY_RING,
    migrationSequence: 2,
    verifyCatalogBinding: async () => ({ owner: true, source: true }),
    auditDecrypt: async input => ({ recorded: true, eventId: input.eventId, contentId: input.contentId }),
  }), 'm4_v2_reader_visible_text_invalid');

  for (const code of ['m4_v2_reader_binding_verification_failed', 'm4_v2_reader_audit_unavailable', 'm4_v2_reader_decrypt_invalid']) {
    try {
      await readM4V2Observation({
        ...base,
        verifyCatalogBinding: async () => { if (code.includes('binding')) throw new Error(literal); return { owner: true, source: true }; },
        auditDecrypt: async input => code.includes('audit') ? Promise.reject(new Error(literal)) : ({ recorded: true, eventId: input.eventId, contentId: input.contentId }),
        ingestKeys: code.includes('decrypt') ? { ...KEY_RING, keys: { ingest: Buffer.alloc(32, 2).toString('base64') } } : KEY_RING,
      });
    } catch (error) {
      assert.equal(error.code, code);
      assertNoLeak(error, literal);
    }
  }
});

test('catalog digest binding fails before callbacks and authenticated GCM tampering fails after audit', async () => {
  const item = createItem({ suffix: 'catalog-binding' });
  const envelope = encrypt(item);
  const row = rowFor(item, envelope);
  for (const catalogRow of [
    { ...row, contentId: 'd'.repeat(64) },
    { ...row, payloadDigest: `hmac-sha256:v1:${'e'.repeat(64)}` },
  ]) {
    const injected = dependencies();
    await assertCode(() => readM4V2Observation({
      catalogRow,
      envelope,
      ingestKeys: KEY_RING,
      migrationSequence: 4,
      verifyCatalogBinding: injected.verifyCatalogBinding,
      auditDecrypt: injected.auditDecrypt,
    }), 'm4_v2_reader_catalog_binding_invalid');
    assert.deepEqual(injected.calls, { binding: [], audit: [] });
  }

  const firstTagCharacter = envelope.tag.startsWith('A') ? 'B' : 'A';
  const tampered = { ...envelope, tag: `${firstTagCharacter}${envelope.tag.slice(1)}` };
  const tamperedRow = { ...row, contentId: ciphertextContentId(tampered) };
  const injected = dependencies();
  await assertCode(() => readM4V2Observation({
    catalogRow: tamperedRow,
    envelope: tampered,
    ingestKeys: KEY_RING,
    migrationSequence: 4,
    verifyCatalogBinding: injected.verifyCatalogBinding,
    auditDecrypt: injected.auditDecrypt,
  }), 'm4_v2_reader_decrypt_invalid');
  assert.equal(injected.calls.binding.length, 1);
  assert.equal(injected.calls.audit.length, 1);

  const aadTampered = { ...envelope, actorId: 'synthetic-other' };
  const aadTamperedRow = { ...row, contentId: ciphertextContentId(aadTampered) };
  const aadInjected = dependencies();
  await assertCode(() => readM4V2Observation({
    catalogRow: aadTamperedRow,
    envelope: aadTampered,
    ingestKeys: KEY_RING,
    migrationSequence: 4,
    verifyCatalogBinding: aadInjected.verifyCatalogBinding,
    auditDecrypt: aadInjected.auditDecrypt,
  }), 'm4_v2_reader_decrypt_invalid');
  assert.equal(aadInjected.calls.binding.length, 1);
  assert.equal(aadInjected.calls.audit.length, 1);
});

test('catalog canonical logical IDs may select a signed key-rotation alias only', async () => {
  const item = createItem({ suffix: 'rotated-logical', logicalKeys: ROTATING_KEY_RING.logicalMessageKeys });
  const envelope = encrypt(item);
  const alias = item.projection.logicalMessageAliases.find(entry => entry.keyVersion === 'logical-k2');
  assert.ok(alias);
  const canonicalRow = { ...rowFor(item, envelope), logicalMessageId: alias.logicalMessageId };
  const injected = dependencies();
  const result = await readM4V2Observation({
    catalogRow: canonicalRow,
    envelope,
    ingestKeys: ROTATING_KEY_RING,
    migrationSequence: 8,
    verifyCatalogBinding: injected.verifyCatalogBinding,
    auditDecrypt: injected.auditDecrypt,
  });
  assert.equal(result.projection.logicalMessageId, alias.logicalMessageId);
  assert.equal(result.projection.keyVersion, alias.keyVersion);
  assert.equal(result.projection.logicalMessageAliases.some(entry => entry.logicalMessageId === alias.logicalMessageId), false);
  assert.deepEqual(result.projection.logicalMessageAliases, [{
    keyVersion: item.projection.keyVersion,
    logicalMessageId: item.projection.logicalMessageId,
  }]);

  const logical = {
    logicalMessageId: alias.logicalMessageId,
    preferredObservationId: result.eventId,
    payloadConflict: false,
    tombstoned: false,
    selectionVersion: 'amf-observation-selection/v1',
    eventIds: [result.eventId],
  };
  assert.equal((await projectM4V2LogicalGroup({
    logical,
    observations: [result],
    integrityFor: () => ({ keyId: 'test-k1', key: Buffer.alloc(32, 5), sentAt: '2026-07-21T12:00:02Z', nonce: 'n'.repeat(16) }),
  })).outcome, 'projected');

  const unrelated = { ...canonicalRow, logicalMessageId: `lmsg_${'f'.repeat(64)}` };
  const rejected = dependencies();
  await assertCode(() => readM4V2Observation({
    catalogRow: unrelated,
    envelope,
    ingestKeys: ROTATING_KEY_RING,
    migrationSequence: 8,
    verifyCatalogBinding: rejected.verifyCatalogBinding,
    auditDecrypt: rejected.auditDecrypt,
  }), 'm4_v2_reader_catalog_invalid');
  assert.deepEqual(rejected.calls, { binding: [], audit: [] });
});

test('malformed binding and audit acknowledgements fail closed without content', async () => {
  const item = createItem({ suffix: 'acks' });
  const envelope = encrypt(item);
  const row = rowFor(item, envelope);
  const base = { catalogRow: row, envelope, ingestKeys: KEY_RING, migrationSequence: 5 };

  let audits = 0;
  await assertCode(() => readM4V2Observation({
    ...base,
    verifyCatalogBinding: async () => ({ owner: true }),
    auditDecrypt: async () => { audits += 1; return {}; },
  }), 'm4_v2_reader_binding_verification_failed');
  assert.equal(audits, 0);

  for (const auditDecrypt of [
    async () => { throw new Error('synthetic audit outage'); },
    async input => ({ recorded: true, eventId: input.eventId, contentId: input.contentId, extra: true }),
    async input => ({ recorded: true, eventId: input.eventId, contentId: 'f'.repeat(64) }),
  ]) {
    await assertCode(() => readM4V2Observation({
      ...base,
      verifyCatalogBinding: async () => ({ owner: true, source: true }),
      auditDecrypt,
    }), 'm4_v2_reader_audit_unavailable');
  }
});

test('all-text arrays obey the safe part contract and fixture remains public-safe', async () => {
  const fixture = JSON.parse(fs.readFileSync(new URL('./fixtures/m4-v2-observation-reader.synthetic.json', import.meta.url), 'utf8'));
  assert.equal(fixture.schema, 'amf.m4-v2-observation-reader-fixture/v1');
  assert.equal(fixture.catalogTagKeyId, 'catalog-k1');
  const parts = [{ type: 'input_text', text: 'first' }, { type: 'output_text', text: 'second' }];
  assert.equal((await read({ suffix: 'parts', value: parts, contentParts: 2 })).result.visibleText, 'first\nsecond');
  const invalid = createItem({ suffix: 'bad-parts', value: [{ type: 'tool', text: 'no' }], contentParts: 1 });
  const invalidEnvelope = encrypt(invalid);
  await assertCode(() => readM4V2Observation({
    catalogRow: rowFor(invalid, invalidEnvelope),
    envelope: invalidEnvelope,
    ingestKeys: KEY_RING,
    migrationSequence: 3,
    verifyCatalogBinding: async () => ({ owner: true, source: true }),
    auditDecrypt: async input => ({ recorded: true, eventId: input.eventId, contentId: input.contentId }),
  }), 'm4_v2_reader_normalized_invalid');

  const tooManyParts = Array.from({ length: 101 }, () => ({ type: 'text', text: 'x' }));
  const tooMany = createItem({ suffix: 'too-many-parts', value: tooManyParts, contentParts: 101 });
  const tooManyEnvelope = encrypt(tooMany);
  await assertCode(() => readM4V2Observation({
    catalogRow: rowFor(tooMany, tooManyEnvelope),
    envelope: tooManyEnvelope,
    ingestKeys: KEY_RING,
    migrationSequence: 4,
    verifyCatalogBinding: async () => ({ owner: true, source: true }),
    auditDecrypt: async input => ({ recorded: true, eventId: input.eventId, contentId: input.contentId }),
  }), 'm4_v2_reader_normalized_invalid');

  const mismatch = createItem({ suffix: 'part-mismatch', value: parts, contentParts: 1 });
  const mismatchEnvelope = encrypt(mismatch);
  await assertCode(() => readM4V2Observation({
    catalogRow: rowFor(mismatch, mismatchEnvelope),
    envelope: mismatchEnvelope,
    ingestKeys: KEY_RING,
    migrationSequence: 5,
    verifyCatalogBinding: async () => ({ owner: true, source: true }),
    auditDecrypt: async input => ({ recorded: true, eventId: input.eventId, contentId: input.contentId }),
  }), 'm4_v2_reader_normalized_invalid');

  const maximumUnicode = createItem({ suffix: 'maximum-unicode', value: '😀'.repeat(65_536) });
  const maximumUnicodeEnvelope = encrypt(maximumUnicode);
  const maximumUnicodeResult = await readM4V2Observation({
    catalogRow: rowFor(maximumUnicode, maximumUnicodeEnvelope),
    envelope: maximumUnicodeEnvelope,
    ingestKeys: KEY_RING,
    migrationSequence: 6,
    verifyCatalogBinding: async () => ({ owner: true, source: true }),
    auditDecrypt: async input => ({ recorded: true, eventId: input.eventId, contentId: input.contentId }),
  });
  assert.equal([...maximumUnicodeResult.visibleText].length, 65_536);
  assert.equal(Buffer.byteLength(maximumUnicodeResult.visibleText, 'utf8'), 262_144);

  const tooLong = createItem({ suffix: 'too-long', value: 'x'.repeat(65_537) });
  const tooLongEnvelope = encrypt(tooLong);
  await assertCode(() => readM4V2Observation({
    catalogRow: rowFor(tooLong, tooLongEnvelope),
    envelope: tooLongEnvelope,
    ingestKeys: KEY_RING,
    migrationSequence: 7,
    verifyCatalogBinding: async () => ({ owner: true, source: true }),
    auditDecrypt: async input => ({ recorded: true, eventId: input.eventId, contentId: input.contentId }),
  }), 'm4_v2_reader_visible_text_invalid');
});

test('OpenClaw signed visible text parts retain only text and fail closed on shape drift', async () => {
  const value = [{
    type: 'text',
    text: 'synthetic signed visible text',
    textSignature: 'synthetic-text-signature',
  }];
  const result = await read({
    sourceKind: 'openclaw',
    role: 'assistant',
    direction: 'outbound',
    value,
    suffix: 'openclaw-signed-text',
  });
  assert.equal(result.result.visibleText, 'synthetic signed visible text');
  assert.equal(JSON.stringify(result.result).includes('synthetic-text-signature'), false);

  for (const [sourceKind, part] of [
    ['codex', value[0]],
    ['openclaw', { ...value[0], textSignature: '' }],
    ['openclaw', { ...value[0], textSignature: 7 }],
    ['openclaw', { ...value[0], extra: true }],
  ]) {
    await assertCode(() => read({
      sourceKind,
      role: 'assistant',
      direction: 'outbound',
      value: [part],
      suffix: crypto.randomUUID(),
    }), 'm4_v2_reader_normalized_invalid');
  }
});
