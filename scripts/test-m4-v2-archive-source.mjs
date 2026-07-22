import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { FileRawStore, MemoryCatalog, SqliteCatalog } from '../src/fabric-store.mjs';
import { ciphertextContentId, normalizeIngestKeyRing, normalizedObservationDigest } from '../src/ingest/raw-event-contract.mjs';
import { EncryptedOutbox } from '../src/ingest/outbox.mjs';
import { deriveEventIdV2, deriveLogicalMessageIds, deriveSessionIdV2, opaqueContextTag } from '../src/ingest/raw-projection-v2.mjs';
import { createM4CrossPhaseIdentityInMemoryAccumulator } from '../src/migration/m4-cross-phase-identity-in-memory-accumulator.mjs';
import { createM4V2ArchiveSource } from '../src/migration/m4-v2-archive-source.mjs';

const INGEST_KEY = Buffer.alloc(32, 7).toString('base64');
const LOGICAL_KEY = Buffer.alloc(32, 8).toString('base64');
const ROTATED_LOGICAL_KEY = Buffer.alloc(32, 10).toString('base64');
const TAG_KEY = Buffer.alloc(32, 9).toString('base64');
const KEYS = {
  keys: { ingest: INGEST_KEY }, digestKey: INGEST_KEY,
  authorizations: { ingest: { actors: ['synthetic-actor'], sourceInstances: ['synthetic-source'] } },
  logicalMessageKeys: { currentKeyVersion: 'logical-k1', keys: { 'logical-k1': LOGICAL_KEY } },
};
const ROTATING_KEYS = { ...KEYS, logicalMessageKeys: {
  currentKeyVersion: 'logical-k2', keys: { 'logical-k1': LOGICAL_KEY, 'logical-k2': ROTATED_LOGICAL_KEY },
} };
const DIGEST_KEY = normalizeIngestKeyRing(KEYS).digestKey;
const START = { id: 'source-checkpoint-001', digest: `sha256:${'a'.repeat(64)}` };
const OWNER = `catalog-k1:${'a'.repeat(64)}`;
const SOURCE = `catalog-k1:${'b'.repeat(64)}`;

function tag(namespace, value) { return opaqueContextTag(namespace, value, TAG_KEY, 'routing-k1'); }
function exactError(action, code) { return assert.rejects(action, error => error?.code === code && error.message === code); }
function integrityFor() {
  let sequence = 0;
  return async () => ({ keyId: 'm4-test-k1', key: Buffer.alloc(32, 5), sentAt: '2026-07-21T12:01:00Z', nonce: `nonce${String(++sequence).padStart(11, '0')}` });
}

function fixtureValues() {
  return [
    item({ suffix: 'user' }), item({ suffix: 'assistant', role: 'assistant' }),
    item({ suffix: 'system', role: 'system', direction: 'internal', contentType: 'structured', value: { ignored: true } }),
    item({ suffix: 'edit-1', logicalSuffix: 'edits', nativeRevision: 1 }),
    item({ suffix: 'edit-2', logicalSuffix: 'edits', nativeRevision: 2 }),
    item({ suffix: 'edit-3', logicalSuffix: 'edits', nativeRevision: 3, deletion: true }),
    item({ suffix: 'conflict-1', logicalSuffix: 'conflict', nativeRevision: null, occurredAt: '2026-07-21T12:00:01.000000000Z' }),
    item({ suffix: 'conflict-2', logicalSuffix: 'conflict', nativeRevision: null, occurredAt: '2026-07-21T12:00:02.000000000Z' }),
    item({ suffix: 'rotated-old', logicalSuffix: 'rotated', value: 'visible rotated', logicalKeys: ROTATING_KEYS.logicalMessageKeys }),
    item({ suffix: 'rotated-new', logicalSuffix: 'rotated', value: 'visible rotated', logicalKeys: ROTATING_KEYS.logicalMessageKeys }),
  ];
}

function item({ suffix, logicalSuffix = suffix, role = 'user', direction = role === 'assistant' ? 'outbound' : 'inbound', contentType = 'text', value = `visible ${suffix}`, nativeRevision = 1, occurredAt = null, deletion = false, logicalKeys = ROTATING_KEYS.logicalMessageKeys } = {}) {
  const senderTag = tag('sender', 'synthetic-sender');
  const conversationTag = tag('conversation', 'synthetic-conversation');
  const logical = { canonicalSenderIdentity: 'synthetic-sender', senderTag, conversationTag, direction,
    nativePlatform: 'synthetic-platform', nativeConversationId: 'synthetic-conversation', nativeMessageId: `native-${logicalSuffix}` };
  const ids = deriveLogicalMessageIds(logical, logicalKeys);
  const rawBytes = Buffer.from(`native-raw-${suffix}`, 'utf8');
  const eventId = deriveEventIdV2({ sourceKind: 'codex', observationClass: 'native', rawBytes });
  const sessionId = deriveSessionIdV2({ sourceKind: 'codex', conversationTag });
  const normalized = { role, contentType: deletion ? 'none' : contentType, value: deletion ? null : value };
  const event = { schema: 'amf.raw-event/v2', eventId, sessionId, occurredAt: occurredAt ?? `2026-07-21T12:00:0${nativeRevision}.000000000Z`,
    source: { runtime: 'codex', subtype: deletion ? 'message.deleted' : 'message' }, logical, normalized,
    raw: { encoding: 'base64', line: rawBytes.toString('base64'), lineEnding: 'lf' } };
  const projection = { schema: 'amf.raw-event-projection/v2', eventId, sessionId, logicalMessageId: ids.logicalMessageId,
    logicalMessageAliases: ids.aliases, derivationVersion: 'amf-logical-message/v1', keyVersion: ids.keyVersion,
    sourceKind: 'codex', observationClass: 'native', direction, conversationKind: 'dm',
    contextTags: { actor: [tag('actor', 'synthetic-actor')], sender: [senderTag], conversation: [conversationTag], room: [tag('room', 'synthetic-room')] },
    subtype: deletion ? 'message.deleted' : 'message', occurredAt: event.occurredAt, editedAt: null, nativeRevision,
    sourceSequence: nativeRevision ?? 1, authoritativeDeletion: deletion, role, contentType: normalized.contentType,
    contentParts: deletion ? 0 : 1, hasContent: !deletion, normalizationVersion: 'amf-observation-normalization/v1',
    normalizedPayloadDigest: normalizedObservationDigest({ event }, DIGEST_KEY) };
  return { event, projection };
}

function encrypt(value) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-m4-source-'));
  try { return new EncryptedOutbox({ rootPath: root, encryptionKey: INGEST_KEY, digestKey: INGEST_KEY,
    sourceInstanceId: 'synthetic-source', actorId: 'synthetic-actor', keyId: 'ingest' }).encrypt(value); }
  finally { fs.rmSync(root, { recursive: true, force: true }); }
}

function catalogRow(value, envelope) {
  return { eventId: value.event.eventId, sessionId: value.event.sessionId, logicalMessageId: value.projection.logicalMessageId,
    contentId: ciphertextContentId(envelope), payloadDigest: envelope.payloadDigest, projection: structuredClone(value.projection),
    ownerTag: OWNER, sourceTag: SOURCE, createdAt: '2026-07-21T12:00:10Z' };
}

async function fixture({ ingestKeys = ROTATING_KEYS, identityCollector = null } = {}) {
  const catalog = new MemoryCatalog();
  const envelopes = new Map();
  const values = fixtureValues();
  for (const value of values) {
    const envelope = encrypt(value); const row = catalogRow(value, envelope);
    if (value.event.raw.line === Buffer.from('native-raw-rotated-old').toString('base64')) row.logicalMessageId = value.projection.logicalMessageAliases[0].logicalMessageId;
    envelopes.set(row.contentId, envelope);
    await catalog.ingestRawEventV2(row, { contentId: row.contentId, mediaType: 'application/json', byteLength: 1, storageRef: `test/${row.contentId}`, createdAt: row.createdAt },
      { id: `audit-${row.eventId.slice(4, 36)}`, ts: row.createdAt, actorTag: OWNER, action: 'synthetic', targetId: row.eventId, details: {} });
  }
  const calls = { binding: [], audit: [], raw: [], pages: 0, pageRequests: [], v1: 0 };
  catalog.listSessionEvents = () => { calls.v1 += 1; throw new Error('v1 forbidden'); };
  const enumerate = catalog.listM4V2LogicalGroups.bind(catalog);
  catalog.listM4V2LogicalGroups = async input => { calls.pages += 1; calls.pageRequests.push(structuredClone(input)); return enumerate(input); };
  class TestRawStore { async getClientCiphertext(contentId) { calls.raw.push(contentId); return structuredClone(envelopes.get(contentId)); } }
  const source = createM4V2ArchiveSource({ catalog, rawStore: new TestRawStore(), ingestKeys,
  verifyCatalogBinding: async input => { calls.binding.push(structuredClone(input)); return { owner: true, source: true }; },
  auditDecrypt: async input => { calls.audit.push(structuredClone(input)); return { recorded: true, eventId: input.eventId, contentId: input.contentId }; },
  integrityFor: integrityFor(), identityCollector, startCheckpoint: START, pageLimit: 2 });
  return { catalog, envelopes, values, source, calls };
}

async function persistentFixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-m4-source-persistent-'));
  const databasePath = path.join(root, 'catalog.sqlite');
  const rawPath = path.join(root, 'raw');
  const rawEncryptionKey = Buffer.alloc(32, 11).toString('base64');
  const catalog = new SqliteCatalog({ databasePath });
  const rawStore = new FileRawStore({ rootPath: rawPath, encryptionKey: rawEncryptionKey, keyId: 'raw-k1' });
  const values = fixtureValues();
  for (const value of values) {
    const envelope = encrypt(value);
    const row = catalogRow(value, envelope);
    if (value.event.raw.line === Buffer.from('native-raw-rotated-old').toString('base64')) row.logicalMessageId = value.projection.logicalMessageAliases[0].logicalMessageId;
    const stored = await rawStore.commitClientCiphertext(row.contentId, envelope);
    await catalog.ingestRawEventV2(row, { ...stored, mediaType: 'application/json', createdAt: row.createdAt },
      { id: `audit-${row.eventId.slice(4, 36)}`, ts: row.createdAt, actorTag: OWNER, action: 'synthetic', targetId: row.eventId, details: {} });
  }
  const createSource = (sourceCatalog = catalog, sourceRawStore = rawStore) => createM4V2ArchiveSource({
    catalog: sourceCatalog,
    rawStore: sourceRawStore,
    ingestKeys: ROTATING_KEYS,
    verifyCatalogBinding: async () => ({ owner: true, source: true }),
    auditDecrypt: async input => ({ recorded: true, eventId: input.eventId, contentId: input.contentId }),
    integrityFor: integrityFor(),
    startCheckpoint: START,
    pageLimit: 2,
  });
  return { root, databasePath, rawPath, rawEncryptionKey, catalog, rawStore, values, source: createSource(), createSource };
}

async function rows(source, request = {}) {
  const output = [];
  for await (const row of source.open({ runId: 'm4-run-001', phase: 'v2-archive', after: START, afterSequence: 0, maxEvents: 1000, ...request })) output.push(row);
  return output;
}

test('real v2 catalog, client ciphertext, reader and projector produce only conversation rows', async () => {
  const env = await fixture(); const output = await rows(env.source);
  assert.deepEqual(output.map(row => row.event.state).sort(), ['active', 'active', 'active', 'active', 'active', 'conflict', 'edited', 'tombstone']);
  assert.equal(output.length, 8);
  assert.equal(env.calls.raw.length, 10);
  assert.equal(env.calls.binding.length, 10);
  assert.equal(env.calls.audit.length, 10);
  assert.ok(env.calls.pages >= 3);
  assert.equal(env.calls.v1, 0);
  const rotatedNew = env.values.find(value => value.event.raw.line === Buffer.from('native-raw-rotated-new').toString('base64'));
  const rotated = output.find(row => row.event.integrity && row.event.visibleText === 'visible rotated');
  assert.ok(rotated);
  assert.notEqual(rotatedNew.projection.logicalMessageId, env.catalog.rawEventsV2.get(rotatedNew.event.eventId).logicalMessageId);
  for (const row of output) {
    assert.deepEqual(Object.keys(row).sort(), ['checkpoint', 'event', 'sequence']);
    assert.equal(JSON.stringify(row.checkpoint).includes('native-raw-'), false);
    assert.equal(JSON.stringify(row).includes(Buffer.from('native-raw-user').toString('base64')), false);
  }
  for (const input of [...env.calls.binding, ...env.calls.audit]) assert.equal(JSON.stringify(input).includes('visible '), false);
  output[0].event.visibleText = 'mutated output';
  assert.equal((await rows(env.source)).some(row => row.event.visibleText === 'mutated output'), false);
});

test('forwards the projector-only identity collector without placing identity data in rows', async () => {
  const blocks = [];
  const env = await fixture({ identityCollector: { async accept(block) { blocks.push(block); } } });
  const output = await rows(env.source);
  assert.ok(blocks.length > 0);
  assert.equal(output.some(row => Object.hasOwn(row, 'identity')), false);
  assert.doesNotMatch(JSON.stringify(blocks), /visibleText|normalizedPayloadDigest|logicalMessageId|nativeEventId|nativeSessionId|integrity|attachment/i);
  const failed = await fixture({ identityCollector: { async accept() { throw new Error('collector unavailable'); } } });
  await exactError(async () => { await rows(failed.source); }, 'm4_v2_source_project_failed');
});

test('replay and resume feed one identity accumulator idempotently without changing rows', async () => {
  const accumulator = createM4CrossPhaseIdentityInMemoryAccumulator({ registrySecret: Buffer.alloc(32, 6) });
  const blocks = [];
  const env = await fixture({ identityCollector: { async accept(block) {
    blocks.push(structuredClone(block));
    return accumulator.accept(block);
  } } });
  const first = await rows(env.source);
  const replay = await rows(env.source);
  const resumed = await rows(env.source, { after: first[2].checkpoint, afterSequence: first[2].sequence });
  const uniqueBlocks = new Set(blocks.map(block => JSON.stringify(block)));
  const sealed = accumulator.seal({ coveredThrough: '2026-07-22T00:00:00Z',
    backfillBinding: { completionDigest: `sha256:${'a'.repeat(64)}`, catalogRevisionDigest: `sha256:${'b'.repeat(64)}` },
    scanCompletion: { complete: true, acceptedGroupCount: uniqueBlocks.size, excludedGroupCount: 1, traversalDigest: `sha256:${'c'.repeat(64)}` } });
  assert.equal(sealed.registry.authority.coverage.eventCount, first.length);
  assert.ok(blocks.length > uniqueBlocks.size);
  assert.deepEqual(replay.map(row => row.checkpoint), first.map(row => row.checkpoint));
  assert.deepEqual(resumed.map(row => row.checkpoint), first.slice(3).map(row => row.checkpoint));
  assert.ok([...first, ...replay, ...resumed].every(row => Object.keys(row).sort().join(',') === 'checkpoint,event,sequence'));
});

test('persistent SQLite catalog and filesystem ciphertext reopen, page and resume without duplicates', async () => {
  const env = await persistentFixture();
  let reopened;
  try {
    const initial = await rows(env.source);
    assert.equal(initial.length, 8);
    assert.ok(initial.every((row, index) => row.sequence === index + 1));
    env.catalog.db.close();

    reopened = new SqliteCatalog({ databasePath: env.databasePath });
    const reopenedRawStore = new FileRawStore({ rootPath: env.rawPath, encryptionKey: env.rawEncryptionKey, keyId: 'raw-k1' });
    const source = env.createSource(reopened, reopenedRawStore);
    const replayed = await rows(source);
    const stableIdentity = row => ({ sequence: row.sequence, checkpoint: row.checkpoint, eventId: row.event.eventId,
      payloadDigest: row.event.integrity.payloadDigest });
    assert.deepEqual(replayed.map(stableIdentity), initial.map(stableIdentity));

    const checkpoint = replayed[2];
    const resumed = await rows(source, { after: checkpoint.checkpoint, afterSequence: checkpoint.sequence });
    assert.deepEqual(resumed.map(stableIdentity), replayed.slice(3).map(stableIdentity));
    assert.equal(new Set([...replayed.slice(0, 3), ...resumed].map(row => row.event.eventId)).size, replayed.length);

    const forgedCheckpoint = { ...checkpoint.checkpoint, digest: `sha256:${'f'.repeat(64)}` };
    await exactError(async () => { for await (const _ of source.open({ runId: 'm4-run-001', phase: 'v2-archive', after: forgedCheckpoint, afterSequence: checkpoint.sequence, maxEvents: 1000 })) {} }, 'm4_v2_source_checkpoint_drift');

    const firstRow = reopened.db.prepare('SELECT event_id,content_id,payload_digest FROM raw_events_v2 ORDER BY event_id LIMIT 1').get();
    reopened.db.prepare('UPDATE raw_events_v2 SET payload_digest=? WHERE event_id=?').run(`hmac-sha256:v1:${'f'.repeat(64)}`, firstRow.event_id);
    await exactError(async () => { await rows(source); }, 'm4_v2_source_read_failed');
    reopened.db.prepare('UPDATE raw_events_v2 SET payload_digest=? WHERE event_id=?').run(firstRow.payload_digest, firstRow.event_id);

    const firstContentId = firstRow.content_id;
    const envelopePath = reopenedRawStore.clientBlobPath(firstContentId);
    const envelope = JSON.parse(fs.readFileSync(envelopePath, 'utf8'));
    envelope.ciphertext = `${envelope.ciphertext.slice(0, -4)}AAAA`;
    fs.writeFileSync(envelopePath, JSON.stringify(envelope));
    await exactError(async () => { await rows(source); }, 'm4_v2_source_envelope_unavailable');
  } finally {
    if (reopened?.db?.open) reopened.db.close();
    if (env.catalog?.db?.open) env.catalog.db.close();
    fs.rmSync(env.root, { recursive: true, force: true });
  }
});

test('the source supplies one completion probe and stable checkpoints, then resumes exactly', async () => {
  const env = await fixture();
  const probe = await rows(env.source, { maxEvents: 2 });
  assert.equal(probe.length, 3);
  const all = await rows(env.source);
  const regenerated = await rows(env.source);
  assert.deepEqual(regenerated.map(row => row.checkpoint), all.map(row => row.checkpoint));
  const middle = all.find(row => row.event.state === 'edited');
  const resumeRequestOffset = env.calls.pageRequests.length;
  const resumed = await rows(env.source, { after: middle.checkpoint, afterSequence: middle.sequence });
  const expectedPredecessor = `lmsg_${(BigInt(`0x${middle.checkpoint.id.slice(5)}`) - 1n).toString(16).padStart(64, '0')}`;
  assert.deepEqual(env.calls.pageRequests[resumeRequestOffset], { after: expectedPredecessor, limit: 2 });
  assert.deepEqual(resumed.map(row => ({ sequence: row.sequence, checkpoint: row.checkpoint })), all.filter(row => row.sequence > middle.sequence).map(row => ({ sequence: row.sequence, checkpoint: row.checkpoint })));
  const afterGroup = all.find(row => row.event.state === 'tombstone');
  const afterGroupRows = await rows(env.source, { after: afterGroup.checkpoint, afterSequence: afterGroup.sequence });
  assert.deepEqual(afterGroupRows.map(row => row.checkpoint), all.filter(row => row.sequence > afterGroup.sequence).map(row => row.checkpoint));
});

test('factory defensively clones ingest keys before later caller mutation', async () => {
  const baseline = await fixture({ ingestKeys: structuredClone(ROTATING_KEYS) });
  const expected = await rows(baseline.source);
  const callerKeys = structuredClone(ROTATING_KEYS);
  const env = await fixture({ ingestKeys: callerKeys });
  callerKeys.keys.ingest = Buffer.alloc(32, 99).toString('base64');
  callerKeys.digestKey = Buffer.alloc(32, 98).toString('base64');
  callerKeys.authorizations.ingest.actors[0] = 'mutated-actor';
  callerKeys.logicalMessageKeys.keys['logical-k2'] = Buffer.alloc(32, 97).toString('base64');
  const actual = await rows(env.source);
  assert.deepEqual(actual.map(row => ({ sequence: row.sequence, checkpoint: row.checkpoint, eventId: row.event.eventId })),
    expected.map(row => ({ sequence: row.sequence, checkpoint: row.checkpoint, eventId: row.event.eventId })));
});

test('resume detects changed group metadata and ciphertext tampering without leaking native content', async () => {
  const env = await fixture(); const all = await rows(env.source);
  const checkpoint = all.find(row => row.event.state === 'edited');
  const added = item({ suffix: 'edit-duplicate', logicalSuffix: 'edits', nativeRevision: 2, value: 'visible edit-2' });
  const envelope = encrypt(added); const row = catalogRow(added, envelope); env.envelopes.set(row.contentId, envelope);
  await env.catalog.ingestRawEventV2(row, { contentId: row.contentId, mediaType: 'application/json', byteLength: 1, storageRef: 'test/changed', createdAt: row.createdAt },
    { id: `audit-${row.eventId.slice(4, 36)}`, ts: row.createdAt, actorTag: OWNER, action: 'synthetic', targetId: row.eventId, details: {} });
  await exactError(async () => { for await (const _ of env.source.open({ runId: 'm4-run-001', phase: 'v2-archive', after: checkpoint.checkpoint, afterSequence: checkpoint.sequence, maxEvents: 1000 })) {} }, 'm4_v2_source_checkpoint_drift');
  const fresh = await fixture(); const first = fresh.envelopes.keys().next().value; const tampered = structuredClone(fresh.envelopes.get(first)); tampered.ciphertext = `${tampered.ciphertext.slice(0, -4)}AAAA`; fresh.envelopes.set(first, tampered);
  await assert.rejects(async () => { await rows(fresh.source); }, error => error?.code === 'm4_v2_source_read_failed' && error.message === 'm4_v2_source_read_failed' && !error.message.includes('native-raw'));
});

test('factory, open, page and group contracts fail before inappropriate callbacks', async () => {
  const dependency = { catalog: { listM4V2LogicalGroups: async () => ({ items: [], next: null }) }, rawStore: { getClientCiphertext: async () => ({}) }, ingestKeys: KEYS,
    verifyCatalogBinding: async () => ({ owner: true, source: true }), auditDecrypt: async () => ({ recorded: true }), integrityFor: integrityFor(), startCheckpoint: START };
  assert.throws(() => createM4V2ArchiveSource({ ...dependency, startCheckpoint: { id: `m4v2-${'a'.repeat(64)}`, digest: START.digest } }), { code: 'm4_v2_source_dependency_invalid' });
  assert.throws(() => createM4V2ArchiveSource({ ...dependency, unknown: true }), { code: 'm4_v2_source_dependency_invalid' });
  assert.throws(() => createM4V2ArchiveSource({ ...dependency, ingestKeys: { keys: {} } }), { code: 'm4_v2_source_dependency_invalid' });
  const source = createM4V2ArchiveSource(dependency);
  assert.throws(() => source.open({ runId: 'm4-run-001', phase: 'v2-archive', after: START, afterSequence: 0, maxEvents: 0 }), { code: 'm4_v2_source_request_invalid' });
  let raw = 0; const bad = createM4V2ArchiveSource({ ...dependency, rawStore: { async getClientCiphertext() { raw += 1; return {}; } },
    catalog: { async listM4V2LogicalGroups() { return { items: [{ logical: {}, observations: [] }], next: null }; } } });
  await exactError(async () => { await rows(bad); }, 'm4_v2_source_catalog_failed');
  assert.equal(raw, 0);
  const paged = createM4V2ArchiveSource({ ...dependency, catalog: { async listM4V2LogicalGroups() { return { items: [], next: `lmsg_${'a'.repeat(64)}` }; } } });
  await exactError(async () => { await rows(paged); }, 'm4_v2_source_catalog_failed');
});
