import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { pathToFileURL } from 'node:url';

import { canonicalJson } from '../src/ingest/transcripts/canonical.mjs';
import { ConversationEventPlaintextOutbox } from '../src/ingest/conversation-event-v3-outbox.mjs';
import { runM4PreservedGroupReplay } from '../src/migration/m4-preserved-group-replay.mjs';
import { prepareM4PreservedUnifiedIndex } from '../src/migration/m4-preserved-unified-index.mjs';
import { prepareM4UnifiedLogicalGroupSource } from '../src/migration/m4-unified-logical-group-source.mjs';

const sha = value => `sha256:${crypto.createHash('sha256').update(value).digest('hex')}`;
const eventId = value => `evt_${String(value).repeat(64).slice(0, 64)}`;
const logicalId = value => `lmsg_${String(value).repeat(64).slice(0, 64)}`;
const authority = { schema: 'amf.m4-group-replay-authority/v1', authorityDigest: sha('unified-authority') };
const origins = ['v2-archive', 'preserved-outbox', 'preserved-deadletter'];

function projection(value, logicalMessageId, options = {}) {
  return { schema: 'amf.raw-event-projection/v2', eventId: eventId(value), sessionId: `ses_${'a'.repeat(64)}`,
    logicalMessageId, logicalMessageAliases: [], derivationVersion: 'amf-logical-message/v1', keyVersion: 'k1', sourceKind: 'codex',
    observationClass: 'native', direction: 'inbound', conversationKind: 'dm', contextTags: {}, subtype: 'message',
    occurredAt: `2026-01-01T00:00:0${options.sequence ?? 1}Z`, editedAt: null, nativeRevision: options.sequence ?? 1,
    sourceSequence: options.sequence ?? 1, authoritativeDeletion: options.deletion === true, role: options.deletion ? 'unknown' : 'user',
    contentType: options.deletion ? 'none' : 'text', contentParts: options.deletion ? 0 : 1, hasContent: options.deletion ? false : true,
    normalizationVersion: 'amf-observation-normalization/v1', normalizedPayloadDigest: `hmac-sha256:k1:${String(value).repeat(64).slice(0, 64)}` };
}

function observation(value, logicalMessageId, options = {}) {
  const item = projection(value, logicalMessageId, options);
  return { eventId: item.eventId, sessionId: item.sessionId, sourceTag: `migration:${'a'.repeat(64)}`,
    migrationSequence: options.sequence ?? 1, projection: item, visibleText: options.deletion ? null : `private ${value}` };
}

function index(origin, position, item, aliases = [item.projection.logicalMessageId]) {
  return { origin, position, legacyEventId: item.eventId,
    recordDigest: sha(canonicalJson({ schema: 'locator/v1', authorityDigest: authority.authorityDigest, origin, position, eventId: item.eventId })),
    projectionDigests: [...aliases].sort().map(logicalMessageId => ({ logicalMessageId,
      projectionDigest: sha(canonicalJson(item.projection)) })) };
}

function prepared(entries, materialized, resolver = async ({ logicalMessageIds }) => logicalMessageIds[0], transform = (_origin, value) => value) {
  const raw = Object.fromEntries(origins.map(origin => [origin, []]));
  for (const item of entries) raw[item.origin].push(item.index);
  const indexes = Object.fromEntries(origins.map(origin => [origin, { schema: 'amf.m4-unified-logical-index/v1',
    authorityDigest: authority.authorityDigest, origin, complete: true, entries: raw[origin] }]));
  const calls = [];
  const materializers = Object.fromEntries(origins.map(origin => [origin, async locator => {
      calls.push(locator); const value = materialized.get(`${origin}:${locator.position}`); if (!value) throw new Error('missing');
      return { ...structuredClone(transform(origin, value)), migrationSequence: locator.migrationSequence };
    }]));
  return prepareM4UnifiedLogicalGroupSource({ authority, indexes, resolveCanonicalLogicalId: resolver, materializers })
    .then(source => ({ source, calls, indexes, materializers }));
}

function request(after = null, limits = {}) {
  return { schema: 'amf.m4-preserved-group-replay-request/v1', authorityDigest: authority.authorityDigest, after,
    maxGroups: limits.maxGroups ?? 100, maxObservations: limits.maxObservations ?? 1000, maxOutputEvents: limits.maxOutputEvents ?? 1000 };
}

async function groups(opened) { const values = []; for await (const value of opened.groups) values.push(value); return values; }

test('coalesces one legacy event across all origins into canonical locators and materializes once', async () => {
  const logical = logicalId('a'); const value = observation('a', logical); const materialized = new Map(); const entries = [];
  origins.forEach((origin, position) => { entries.push({ origin, index: index(origin, position + 1, value) }); materialized.set(`${origin}:${position + 1}`, value); });
  const { source, calls } = await prepared(entries, materialized); const opened = await source.open(request()); const [group] = await groups(opened);
  assert.equal(group.descriptor.members.length, 1); assert.equal(group.descriptor.members[0].locators.length, 3);
  assert.equal(group.observations.length, 1); assert.equal(calls.length, 3); assert.equal((await opened.completion()).complete, true);
  assert.deepEqual(calls.map(item => item.migrationSequence), [1, 1, 1]);
  assert.equal(JSON.stringify(group.descriptor).includes('private '), false);
});

test('keeps a split edit and tombstone in one recomputed logical group', async () => {
  const logical = logicalId('b'); const edit = observation('b', logical, { sequence: 1 }); const tombstone = observation('c', logical, { sequence: 2, deletion: true });
  const materialized = new Map([['v2-archive:1', edit], ['preserved-deadletter:2', tombstone]]);
  const { source } = await prepared([{ origin: 'v2-archive', index: index('v2-archive', 1, edit) }, { origin: 'preserved-deadletter', index: index('preserved-deadletter', 2, tombstone) }], materialized);
  const [group] = await groups(await source.open(request()));
  assert.equal(group.observations.length, 2); assert.equal(group.logical.tombstoned, true);
});

test('coalesces alias-indexed equal payload records and rejects changed projection evidence', async () => {
  const canonical = logicalId('c'); const alias = logicalId('d'); const first = observation('d', canonical); const second = observation('e', canonical);
  const materialized = new Map([['v2-archive:1', first], ['preserved-outbox:2', second]]);
  const { source } = await prepared([{ origin: 'v2-archive', index: index('v2-archive', 1, first, [alias, canonical]) }, { origin: 'preserved-outbox', index: index('preserved-outbox', 2, second, [alias, canonical]) }], materialized,
  async () => canonical);
  const [group] = await groups(await source.open(request())); assert.equal(group.descriptor.members.length, 2);
  const changed = structuredClone(index('preserved-outbox', 2, first));
  changed.projectionDigests.find(item => item.logicalMessageId === canonical).projectionDigest = sha('changed');
  await assert.rejects(() => prepared([{ origin: 'v2-archive', index: index('v2-archive', 1, first) }, { origin: 'preserved-outbox', index: changed }], materialized), { code: 'm4_unified_index_mismatch' });
});

test('resumes by exact digest and stops cleanly at group and member boundaries', async () => {
  const one = observation('f', logicalId('e')); const two = observation('a', logicalId('f')); const pair = observation('b', logicalId('f'));
  const materialized = new Map([['v2-archive:1', one], ['v2-archive:2', two], ['v2-archive:3', pair]]);
  const { source } = await prepared([{ origin: 'v2-archive', index: index('v2-archive', 1, one) }, { origin: 'v2-archive', index: index('v2-archive', 2, two) }, { origin: 'v2-archive', index: index('v2-archive', 3, pair) }], materialized);
  const first = await source.open(request(null, { maxGroups: 1 })); const [firstGroup] = await groups(first); assert.equal((await first.completion()).complete, false);
  const resumed = await source.open(request(firstGroup.descriptor.groupDigest)); const resumedGroups = await groups(resumed); assert.equal(resumedGroups.length, 1); assert.equal((await resumed.completion()).complete, true);
  const bounded = await source.open(request(null, { maxObservations: 1 })); assert.deepEqual(await groups(bounded), [firstGroup]); assert.equal((await bounded.completion()).complete, false);
  await assert.rejects(() => source.open(request(sha('unknown'))), { code: 'm4_unified_resume_invalid' });
});

test('paginates more than 100 prepared groups and rejects divergent duplicate locators', async () => {
  const entries = []; const materialized = new Map();
  for (let position = 1; position <= 101; position += 1) {
    const hex = position.toString(16).padStart(2, '0'); const value = observation(hex, logicalId(hex));
    entries.push({ origin: 'v2-archive', index: index('v2-archive', position, value) }); materialized.set(`v2-archive:${position}`, value);
  }
  const { source } = await prepared(entries, materialized); const page = await source.open(request()); const pageGroups = await groups(page);
  assert.equal(pageGroups.length, 100); assert.equal((await page.completion()).complete, false);
  const tail = await source.open(request(pageGroups.at(-1).descriptor.groupDigest)); assert.equal((await groups(tail)).length, 1); assert.equal((await tail.completion()).complete, true);

  const logical = logicalId('a'); const value = observation('a', logical); const duplicate = structuredClone(index('preserved-outbox', 1, value));
  const divergent = await prepared([{ origin: 'v2-archive', index: index('v2-archive', 1, value) }, { origin: 'preserved-outbox', index: duplicate }],
    new Map([['v2-archive:1', value], ['preserved-outbox:1', value]]), undefined,
  (origin, item) => origin === 'preserved-outbox' ? { ...item, visibleText: 'different private text' } : item);
  await assert.rejects(async () => { const opened = await divergent.source.open(request()); await groups(opened); }, { code: 'm4_unified_materialization_mismatch' });
  const collision = observation('b', logicalId('b'));
  await assert.rejects(() => prepared([{ origin: 'v2-archive', index: index('v2-archive', 1, value) }, { origin: 'v2-archive', index: index('v2-archive', 1, collision) }], materialized), { code: 'm4_unified_index_mismatch' });
  await assert.rejects(() => prepared([{ origin: 'v2-archive', index: index('v2-archive', 1, value) },
    { origin: 'v2-archive', index: index('v2-archive', 2, value) }], materialized), { code: 'm4_unified_index_mismatch' });
});

test('snapshots index values and materializer functions during preparation', async () => {
  const value = observation('c', logicalId('c')); const materialized = new Map([['v2-archive:1', value]]);
  const setup = await prepared([{ origin: 'v2-archive', index: index('v2-archive', 1, value) }], materialized);
  setup.indexes['v2-archive'].entries.length = 0;
  setup.materializers['v2-archive'] = async () => { throw new Error('mutated'); };
  const [group] = await groups(await setup.source.open(request()));
  assert.equal(group.descriptor.members.length, 1);
});

const rawAdapterRoot = process.env.AMF_RAW_ADAPTER_PATH
  ? (fs.existsSync(path.join(process.env.AMF_RAW_ADAPTER_PATH, 'src'))
    ? process.env.AMF_RAW_ADAPTER_PATH
    : path.join(process.env.AMF_RAW_ADAPTER_PATH, 'runtime', 'raw-adapters'))
  : null;

test('optionally crosses preserved reader/decoder through unified source and Fabric delivery', { skip: rawAdapterRoot === null }, async () => {
  const load = file => import(pathToFileURL(path.join(rawAdapterRoot, 'src', file)).href);
  const [{ M4PreservedQueueReader }, { createM4PreservedObservationDecoder }, { createRawEnvelopeDecoder, EncryptedRawOutbox },
    { createPauseCheckpoint }, { RawProjectionBuilder }] = await Promise.all([
    load('m4-preserved-queue.mjs'), load('m4-preserved-observation.mjs'), load('outbox.mjs'),
    load('pause-checkpoint.mjs'), load('projection.mjs'),
  ]);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-m4-unified-cross-'));
  const encryptionKey = Buffer.alloc(32, 1).toString('base64'); const digestKey = Buffer.alloc(32, 2).toString('base64');
  const logicalKey = Buffer.alloc(32, 4).toString('base64'); const rotatedLogicalKey = Buffer.alloc(32, 6).toString('base64');
  const routingKey = Buffer.alloc(32, 5).toString('base64');
  const eventKey = Buffer.alloc(32, 9); const delivered = []; let checkpoint = null;
  try {
    const outboxRoot = path.join(root, 'raw-outbox'); const cursorRoot = path.join(root, 'cursors'); fs.mkdirSync(cursorRoot, { mode: 0o700 });
    fs.writeFileSync(path.join(cursorRoot, 'cursor.enc.json'), 'cursor', { mode: 0o600 });
    const nativePath = path.join(root, 'native.jsonl'); fs.writeFileSync(nativePath, '{"type":"synthetic"}\n', { mode: 0o600 });
    const rawOutbox = new EncryptedRawOutbox({ rootPath: outboxRoot, encryptionKey, digestKey, keyId: 'client-v1',
      sourceInstanceId: 'synthetic-runtime', actorId: 'synthetic-actor', maxAttempts: 1 });
    const builder = new RawProjectionBuilder({ digestKey, payloadKeyVersion: 'v1',
      logicalKeyRing: { currentKeyVersion: 'logical-v2', keys: { 'logical-v1': logicalKey, 'logical-v2': rotatedLogicalKey } },
      routingKeyRing: { currentKeyVersion: 'routing-v1', keys: { 'routing-v1': routingKey } } });
    const build = (revision, deleted) => builder.build({ runtime: 'openclaw', rawBytes: Buffer.from(JSON.stringify({ revision, deleted })),
      value: { type: 'message', id: `revision-${revision}`, stableNativeMessageId: 'same-message', revision,
        timestamp: `2026-07-22T00:00:0${revision}Z`, authoritativeDeletion: deleted,
        message: { role: 'user', content: deleted ? 'discarded tombstone source' : 'cross-repo visible edit' } },
      defaults: { sessionId: 'synthetic-session', canonicalSenderIdentity: 'person:synthetic', actorIdentity: 'synthetic-actor' } });
    const edit = build(1, false); const tombstone = build(2, true); rawOutbox.enqueue(edit); rawOutbox.enqueue(tombstone);
    rawOutbox.defer(rawOutbox.readRecord(tombstone.event.eventId), Object.assign(new Error('dead'), { permanent: true, code: 'synthetic_dead' }));
    const pausePath = path.join(root, 'pause.json'); createPauseCheckpoint({ config: { sourceInstanceId: 'synthetic-runtime', actorId: 'synthetic-actor', outboxPath: outboxRoot, cursorPath: cursorRoot },
      sources: [{ runtime: 'claude', filePath: nativePath }], manifestId: 'pause-manifest-synthetic', revision: 1, keyId: 'migration-key-synthetic',
      outputPath: pausePath, collectorBindingKey: Buffer.alloc(32, 3) });
    const reader = new M4PreservedQueueReader({ outboxPath: outboxRoot, checkpointDocument: JSON.parse(fs.readFileSync(pausePath, 'utf8')) });
    const queueAuthority = reader.authority(); const authorityDigest = sha(canonicalJson(queueAuthority));
    const decoder = createM4PreservedObservationDecoder({ envelopeDecoder: createRawEnvelopeDecoder({ encryptionKey, digestKey, keyId: 'client-v1', sourceInstanceId: 'synthetic-runtime', actorId: 'synthetic-actor' }) });
    const bridge = await prepareM4PreservedUnifiedIndex({ authority: { schema: 'amf.m4-group-replay-authority/v1', authorityDigest }, reader, decoder,
      sourceTag: `migration:${'b'.repeat(64)}` });
    const canonicalAlias = bridge.indexes['preserved-outbox'].entries[0].projectionDigests.find(item => item.logicalMessageId !== edit.projection.logicalMessageId);
    assert.ok(canonicalAlias); assert.equal(bridge.indexes['preserved-deadletter'].entries[0].projectionDigests.some(item => item.logicalMessageId === canonicalAlias.logicalMessageId), true);
    const source = await prepareM4UnifiedLogicalGroupSource({ authority: { schema: 'amf.m4-group-replay-authority/v1', authorityDigest },
      indexes: { 'v2-archive': { schema: 'amf.m4-unified-logical-index/v1', authorityDigest, origin: 'v2-archive', complete: true, entries: [] },
        'preserved-outbox': bridge.indexes['preserved-outbox'], 'preserved-deadletter': bridge.indexes['preserved-deadletter'] },
      resolveCanonicalLogicalId: async () => canonicalAlias.logicalMessageId,
      materializers: { 'v2-archive': async () => { throw new Error('unexpected archive materialization'); },
        'preserved-outbox': bridge.materializers['preserved-outbox'], 'preserved-deadletter': bridge.materializers['preserved-deadletter'] } });
    const opened = await source.open({ schema: 'amf.m4-preserved-group-replay-request/v1', authorityDigest, after: null,
      maxGroups: 100, maxObservations: 1000, maxOutputEvents: 1000 }); const privateGroups = await groups(opened); assert.equal(privateGroups.length, 1);
    assert.equal(privateGroups[0].descriptor.members.length, 2); assert.equal(privateGroups[0].logical.tombstoned, true);
    assert.equal(privateGroups[0].logical.logicalMessageId, canonicalAlias.logicalMessageId);
    assert.equal(JSON.stringify(privateGroups[0].descriptor).includes('cross-repo visible edit'), false);
    const deliveryOutbox = new ConversationEventPlaintextOutbox({ rootPath: path.join(root, 'delivery-outbox'), resolveIntegrityKey: keyId => keyId === 'delivery-k1' ? eventKey : null,
      clock: () => Date.parse('2026-07-22T01:00:00Z'), nonceFactory: () => 'crossrepononce00001' });
    const result = await runM4PreservedGroupReplay({ authority: { schema: 'amf.m4-group-replay-authority/v1', authorityDigest }, source,
      outbox: deliveryOutbox, sink: { async deliver(event, metadata) { delivered.push({ event, metadata }); return { acknowledged: true, eventId: event.eventId, payloadDigest: metadata.payloadDigest, status: 'stored' }; } },
    checkpointStore: { async load() { return checkpoint; }, async commit(value) { checkpoint = structuredClone(value); return structuredClone(value); } },
    integrityFor: async ({ eventId, state, revision }) => ({ keyId: 'delivery-k1', key: eventKey, sentAt: '2026-07-22T01:00:00Z', nonce: `${state}${revision}${eventId.slice(5, 16)}`.padEnd(16, '0').slice(0, 16) }) });
    assert.equal(result.groups, 1); assert.equal(result.outputEvents, 2); assert.deepEqual(delivered.map(item => item.event.state), ['active', 'tombstone']);
    assert.equal(JSON.stringify(result).includes('cross-repo visible edit'), false); assert.equal(JSON.stringify(checkpoint).includes('cross-repo visible edit'), false);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
