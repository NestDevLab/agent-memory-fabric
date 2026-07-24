import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { MemoryCatalog } from '../src/fabric-store.mjs';
import { ciphertextContentId, normalizeIngestKeyRing, normalizedObservationDigest } from '../src/ingest/raw-event-contract.mjs';
import { EncryptedOutbox } from '../src/ingest/outbox.mjs';
import { deriveEventIdV2, deriveLogicalMessageIds, deriveSessionIdV2, opaqueContextTag } from '../src/ingest/raw-projection-v2.mjs';
import { prepareM4V2UnifiedIndex } from '../src/migration/m4-v2-unified-index.mjs';

const INGEST_KEY = Buffer.alloc(32, 7).toString('base64');
const LOGICAL_KEY = Buffer.alloc(32, 8).toString('base64');
const ROTATED_LOGICAL_KEY = Buffer.alloc(32, 10).toString('base64');
const TAG_KEY = Buffer.alloc(32, 9).toString('base64');
const INGEST_KEYS = {
  keys: { ingest: INGEST_KEY }, digestKey: INGEST_KEY,
  authorizations: { ingest: { actors: ['synthetic-actor'], sourceInstances: ['synthetic-source'] } },
  logicalMessageKeys: { currentKeyVersion: 'logical-k2', keys: { 'logical-k1': LOGICAL_KEY, 'logical-k2': ROTATED_LOGICAL_KEY } },
};
const DIGEST_KEY = normalizeIngestKeyRing(INGEST_KEYS).digestKey;
const AUTHORITY = { schema: 'amf.m4-group-replay-authority/v1', authorityDigest: sha('v2-unified-authority') };
const OWNER = `catalog-k1:${'a'.repeat(64)}`;
const SOURCE = `catalog-k1:${'b'.repeat(64)}`;

function sha(value) { return `sha256:${crypto.createHash('sha256').update(value).digest('hex')}`; }
function tag(namespace, value) { return opaqueContextTag(namespace, value, TAG_KEY, 'routing-k1'); }
function item({ suffix, nativeMessageId = suffix, revision = 1, deletion = false } = {}) {
  const senderTag = tag('sender', 'synthetic-sender'); const conversationTag = tag('conversation', 'synthetic-conversation');
  const logical = { canonicalSenderIdentity: 'synthetic-sender', senderTag, conversationTag, direction: 'inbound', nativePlatform: 'synthetic-platform',
    nativeConversationId: 'synthetic-conversation', nativeMessageId };
  const ids = deriveLogicalMessageIds(logical, INGEST_KEYS.logicalMessageKeys);
  const rawBytes = Buffer.from(`native-raw-${suffix}`, 'utf8');
  const eventId = deriveEventIdV2({ sourceKind: 'codex', observationClass: 'native', rawBytes });
  const sessionId = deriveSessionIdV2({ sourceKind: 'codex', conversationTag });
  const normalized = { role: deletion ? 'unknown' : 'user', contentType: deletion ? 'none' : 'text',
    value: deletion ? null : `visible ${suffix} ${'x'.repeat(1_400)}` };
  const event = { schema: 'amf.raw-event/v2', eventId, sessionId, occurredAt: `2026-07-22T00:00:0${revision}.000000000Z`,
    source: { runtime: 'codex', subtype: deletion ? 'message.deleted' : 'message' }, logical, normalized,
    raw: { encoding: 'base64', line: rawBytes.toString('base64'), lineEnding: 'lf' } };
  const projection = { schema: 'amf.raw-event-projection/v2', eventId, sessionId, logicalMessageId: ids.logicalMessageId,
    logicalMessageAliases: ids.aliases, derivationVersion: 'amf-logical-message/v1', keyVersion: ids.keyVersion,
    sourceKind: 'codex', observationClass: 'native', direction: 'inbound', conversationKind: 'dm',
    contextTags: { actor: [tag('actor', 'synthetic-actor')], sender: [senderTag], conversation: [conversationTag], room: [tag('room', 'synthetic-room')] },
    subtype: deletion ? 'message.deleted' : 'message', occurredAt: event.occurredAt, editedAt: null, nativeRevision: revision,
    sourceSequence: revision, authoritativeDeletion: deletion, role: normalized.role, contentType: normalized.contentType,
    contentParts: deletion ? 0 : 1, hasContent: !deletion, normalizationVersion: 'amf-observation-normalization/v1',
    normalizedPayloadDigest: normalizedObservationDigest({ event }, DIGEST_KEY) };
  return { event, projection };
}
function encrypt(value) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-m4-v2-unified-encrypt-'));
  try {
    return new EncryptedOutbox({ rootPath: root, encryptionKey: INGEST_KEY, digestKey: INGEST_KEY,
      sourceInstanceId: 'synthetic-source', actorId: 'synthetic-actor', keyId: 'ingest' }).encrypt(value);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}
function catalogRow(value, envelope, logicalMessageId = value.projection.logicalMessageId) {
  return { eventId: value.event.eventId, sessionId: value.event.sessionId, logicalMessageId,
    contentId: ciphertextContentId(envelope), payloadDigest: envelope.payloadDigest, projection: structuredClone(value.projection),
    ownerTag: OWNER, sourceTag: SOURCE, createdAt: '2026-07-22T00:00:10Z' };
}
async function fixture(values) {
  const catalog = new MemoryCatalog(); const envelopes = new Map(); const calls = { raw: 0, audit: 0, binding: 0 };
  for (const { value, selectAlias = false, omitEnvelope = false } of values) {
    const envelope = encrypt(value); const selected = selectAlias ? value.projection.logicalMessageAliases[0].logicalMessageId : value.projection.logicalMessageId;
    const row = catalogRow(value, envelope, selected);
    if (!omitEnvelope) envelopes.set(row.contentId, envelope);
    await catalog.ingestRawEventV2(row, { contentId: row.contentId, mediaType: 'application/json', byteLength: 1,
      storageRef: `test/${row.contentId}`, createdAt: row.createdAt },
    { id: `audit-${row.eventId.slice(4, 36)}`, ts: row.createdAt, actorTag: OWNER, action: 'synthetic', targetId: row.eventId, details: {} });
  }
  const rawStore = { async getClientCiphertext(contentId) { calls.raw += 1; return structuredClone(envelopes.get(contentId)); } };
  const input = { authority: AUTHORITY, catalog, rawStore, ingestKeys: INGEST_KEYS,
    verifyCatalogBinding: async () => { calls.binding += 1; return { owner: true, source: true }; },
    auditDecrypt: async request => { calls.audit += 1; return { recorded: true, eventId: request.eventId, contentId: request.contentId }; },
    pageLimit: 1 };
  return { catalog, envelopes, input, calls };
}
function locator(entry, canonicalLogicalMessageId, migrationSequence = 1) {
  return { authorityDigest: AUTHORITY.authorityDigest, canonicalLogicalMessageId, migrationSequence,
    legacyEventId: entry.legacyEventId,
    projectionDigest: entry.projectionDigests.find(item => item.logicalMessageId === canonicalLogicalMessageId).projectionDigest,
    origin: 'v2-archive', position: entry.position, recordDigest: entry.recordDigest };
}

test('indexes real v2 catalog envelopes without plaintext and materializes a rotated alias', async () => {
  const first = item({ suffix: 'first' }); const rotated = item({ suffix: 'rotated' });
  const env = await fixture([{ value: rotated, selectAlias: true }, { value: first }]);
  const bridge = await prepareM4V2UnifiedIndex(env.input);
  assert.equal(bridge.index.complete, true); assert.equal(bridge.totalEntries, 2); assert.equal(bridge.index.entries.length, 2);
  assert.deepEqual(bridge.attestation, { schema: 'amf.m4-v2-unified-index-attestation/v1',
    authorityDigest: AUTHORITY.authorityDigest, archiveDigest: bridge.attestation.archiveDigest,
    totalEntries: 2, totalBytes: bridge.totalBytes });
  assert.match(bridge.attestation.archiveDigest, /^sha256:[a-f0-9]{64}$/);
  assert.equal(JSON.stringify(bridge.index).includes('visible '), false); assert.equal(JSON.stringify(bridge.index).includes('ciphertext'), false);
  assert.throws(() => bridge.index.entries[0].projectionDigests.push({}), TypeError);
  const entry = bridge.index.entries.find(candidate => candidate.legacyEventId === rotated.event.eventId);
  const materialized = await bridge.materializer(locator(entry, rotated.projection.logicalMessageId, 7));
  assert.equal(materialized.projection.logicalMessageId, rotated.projection.logicalMessageId);
  assert.equal(materialized.migrationSequence, 7); assert.match(materialized.visibleText, /^visible rotated/);
  assert.equal(env.calls.audit, 1); assert.equal(env.calls.binding, 1);
  assert.equal(env.calls.raw, 4, 'preparation and materialization each complete the two-row scan');
});

test('indexes and materializes an ineligible catalog row without opening unavailable RAW', async () => {
  const proposal = item({ suffix: 'proposal-only' });
  Object.assign(proposal.projection, {
    direction: 'unknown',
    conversationKind: 'unknown',
    role: 'unknown',
    contentType: 'none',
    contentParts: 0,
    hasContent: false
  });
  const env = await fixture([{ value: proposal, omitEnvelope: true }]);
  const bridge = await prepareM4V2UnifiedIndex(env.input);
  assert.equal(bridge.totalEntries, 1);
  assert.equal(bridge.totalBytes, 0);
  assert.equal(env.calls.raw, 0);
  const entry = bridge.index.entries[0];
  const materialized = await bridge.materializer(locator(entry, proposal.projection.logicalMessageId, 3));
  assert.equal(materialized.visibleText, null);
  assert.equal(materialized.projection.role, 'unknown');
  assert.equal(materialized.migrationSequence, 3);
  assert.equal(env.calls.raw, 0);
  assert.equal(env.calls.audit, 0);
  assert.equal(env.calls.binding, 0);
});

test('reopen detects exact envelope drift and never includes content in its error', async () => {
  const value = item({ suffix: 'drift' }); const env = await fixture([{ value }]);
  const bridge = await prepareM4V2UnifiedIndex(env.input); const entry = bridge.index.entries[0];
  const contentId = env.envelopes.keys().next().value; const changed = structuredClone(env.envelopes.get(contentId));
  changed.ciphertext = `${changed.ciphertext.slice(0, -4)}AAAA`; env.envelopes.set(contentId, changed);
  await assert.rejects(() => bridge.materializer(locator(entry, value.projection.logicalMessageId)), error =>
    ['m4_v2_unified_envelope_invalid', 'm4_v2_unified_materialization_mismatch'].includes(error?.code)
      && error.message === error.code && !error.message.includes('visible drift'));
});

test('reopen rejects a valid archive addition outside the requested position', async () => {
  const first = item({ suffix: 'stable' }); const env = await fixture([{ value: first }]);
  const bridge = await prepareM4V2UnifiedIndex(env.input); const entry = bridge.index.entries[0];
  const added = item({ suffix: 'added' }); const envelope = encrypt(added); const row = catalogRow(added, envelope);
  env.envelopes.set(row.contentId, envelope);
  await env.catalog.ingestRawEventV2(row, { contentId: row.contentId, mediaType: 'application/json', byteLength: 1,
    storageRef: `test/${row.contentId}`, createdAt: row.createdAt },
  { id: `audit-${row.eventId.slice(4, 36)}`, ts: row.createdAt, actorTag: OWNER, action: 'synthetic', targetId: row.eventId, details: {} });
  await assert.rejects(() => bridge.materializer(locator(entry, first.projection.logicalMessageId)),
    { code: 'm4_v2_unified_materialization_mismatch' });
});

test('rejects bounds, unsigned aliases, duplicate events, and caller key mutation', async () => {
  const value = item({ suffix: 'guards' }); const env = await fixture([{ value }]);
  await assert.rejects(() => prepareM4V2UnifiedIndex({ ...env.input, maxBytes: 1 }), { code: 'm4_v2_unified_bound_invalid' });
  const callerKeys = structuredClone(INGEST_KEYS); const bridge = await prepareM4V2UnifiedIndex({ ...env.input, ingestKeys: callerKeys });
  callerKeys.keys.ingest = Buffer.alloc(32, 99).toString('base64');
  const entry = bridge.index.entries[0]; await bridge.materializer(locator(entry, value.projection.logicalMessageId));
  await assert.rejects(() => bridge.materializer({ ...locator(entry, value.projection.logicalMessageId),
    canonicalLogicalMessageId: `lmsg_${'f'.repeat(64)}` }), { code: 'm4_v2_unified_materialization_mismatch' });

  const envelope = encrypt(value); const primary = catalogRow(value, envelope); const alias = catalogRow(value, envelope, value.projection.logicalMessageAliases[0].logicalMessageId);
  const group = row => ({ logical: { logicalMessageId: row.logicalMessageId, preferredObservationId: row.eventId,
    payloadConflict: false, tombstoned: false, selectionVersion: 'amf-observation-selection/v1', eventIds: [row.eventId] }, observations: [row] });
  const duplicateCatalog = { async listM4V2LogicalGroups() { return { items: [group(primary), group(alias)].sort((a, b) => a.logical.logicalMessageId.localeCompare(b.logical.logicalMessageId)), next: null }; } };
  await assert.rejects(() => prepareM4V2UnifiedIndex({ ...env.input, catalog: duplicateCatalog,
    rawStore: { async getClientCiphertext() { return structuredClone(envelope); } }, pageLimit: 2 }), { code: 'm4_v2_unified_catalog_invalid' });
});

test('snapshots methods and maps hostile dependency failures to fixed codes', async () => {
  const value = item({ suffix: 'snapshot' }); const env = await fixture([{ value }]); const bridge = await prepareM4V2UnifiedIndex(env.input);
  env.input.catalog.listM4V2LogicalGroups = async () => { throw new Error('mutated'); };
  env.input.rawStore.getClientCiphertext = async () => { throw new Error('mutated'); };
  const entry = bridge.index.entries[0]; await bridge.materializer(locator(entry, value.projection.logicalMessageId));
  const hostile = new Proxy({}, { ownKeys() { throw new Error('private hostile value'); } });
  await assert.rejects(() => prepareM4V2UnifiedIndex(hostile), error => error.code === 'm4_v2_unified_dependency_invalid'
    && error.message === 'm4_v2_unified_dependency_invalid');
  const hostilePage = new Proxy({}, { getPrototypeOf() { throw new Error('private page value'); } });
  const hostileEnv = await fixture([{ value }]);
  await assert.rejects(() => prepareM4V2UnifiedIndex({ ...hostileEnv.input,
    catalog: { async listM4V2LogicalGroups() { return hostilePage; } } }),
  error => error.code === 'm4_v2_unified_catalog_invalid' && error.message === 'm4_v2_unified_catalog_invalid');
  const hostileEnvelope = new Proxy({}, { getPrototypeOf() { throw Object.defineProperty({}, 'code', { get() { throw new Error('private error value'); } }); } });
  await assert.rejects(() => prepareM4V2UnifiedIndex({ ...hostileEnv.input,
    rawStore: { async getClientCiphertext() { return hostileEnvelope; } } }),
  error => error.code === 'm4_v2_unified_envelope_invalid' && error.message === 'm4_v2_unified_envelope_invalid');
  const normalEnvelope = hostileEnv.envelopes.values().next().value;
  await assert.rejects(() => prepareM4V2UnifiedIndex({ ...hostileEnv.input, maxCiphertextBytes: 1_024,
    rawStore: { async getClientCiphertext() { return { ...normalEnvelope, ciphertext: 'A'.repeat(1_372) }; } } }),
  error => error.code === 'm4_v2_unified_bound_invalid' && error.message === 'm4_v2_unified_bound_invalid');
  const hostileLocator = new Proxy({}, { ownKeys() { throw new Error('private locator value'); } });
  await assert.rejects(() => bridge.materializer(hostileLocator),
    error => error.code === 'm4_v2_unified_materialization_invalid' && error.message === 'm4_v2_unified_materialization_invalid');
});
