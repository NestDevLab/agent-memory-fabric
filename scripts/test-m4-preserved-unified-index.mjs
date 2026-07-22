import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import { prepareM4PreservedUnifiedIndex } from '../src/migration/m4-preserved-unified-index.mjs';

const sha = value => `sha256:${crypto.createHash('sha256').update(value).digest('hex')}`;
const event = value => `evt_${String(value).repeat(64).slice(0, 64)}`;
const logical = value => `lmsg_${String(value).repeat(64).slice(0, 64)}`;
const fabricAuthority = { schema: 'amf.m4-group-replay-authority/v1', authorityDigest: sha('fabric') };
const source = (endInclusive, chain = sha(`chain-${endInclusive}`)) => ({ pauseCheckpoint: { id: 'pause-001', digest: sha('pause') },
  interval: { startExclusive: 0, endInclusive, chain: { id: 'chain-001', digest: chain } }, initialCheckpoint: { id: 'initial-001', digest: sha('initial') } });
const readerAuthority = (outbox = 0, deadletter = 0) => ({ acknowledgements: { id: 'ack-001', digest: sha('ack') }, sources: { outbox: source(outbox), deadletter: source(deadletter) } });
const raw = (sourceKind, position, value, secret = `private-${value}`) => ({ sourceKind, position, legacyEventId: event(value), envelopeDigest: sha(`${sourceKind}:${position}:${value}`), ciphertext: Buffer.from(secret) });

function reader(records = {}, options = {}) {
  const queues = { outbox: records.outbox ?? [], deadletter: records.deadletter ?? [] };
  const attestation = options.authority ?? readerAuthority(queues.outbox.length, queues.deadletter.length);
  const calls = { open: [], positions: [] };
  const openResult = (sourceKind, requested, positions = null) => { const stream = (async function* () { for (const value of queues[sourceKind].filter(item => positions === null || positions.includes(item.position))) { const yielded = { ...value, ciphertext: Buffer.from(value.ciphertext) }; options.seenYielded?.push(yielded.ciphertext); yield yielded; } if (positions !== null && options.trailing) { const yielded = { ...options.trailing, ciphertext: Buffer.from(options.trailing.ciphertext) }; options.seenYielded?.push(yielded.ciphertext); yield yielded; } })(); return { schema: positions ? 'amf.m4-preserved-position-reader/v1' : 'amf.m4-preserved-replay-reader/v2', sourceKind,
    pauseCheckpoint: structuredClone(requested.pauseCheckpoint), interval: structuredClone(requested.interval), ...(positions ? { positions: options.positionsDrift ? [positions[0] + 1] : positions } : {}),
    records: options.malformedStep ? { [Symbol.asyncIterator]() { let emitted = false; return {
      async next() { if (emitted) return { done: true }; emitted = true; const value = { ...queues[sourceKind][0], ciphertext: Buffer.from(queues[sourceKind][0].ciphertext) }; options.seenYielded?.push(value.ciphertext); return { done: 'invalid', value }; },
      async return() { return { done: true }; },
    }; } } : options.closeThrow ? { [Symbol.asyncIterator]() { return { next: stream.next.bind(stream), return: async () => {
      if (options.closeThrow === 'hostile') { const error = new Error('private close detail'); Object.defineProperty(error, 'code', { get() { throw new Error('private getter detail'); } }); throw error; }
      throw new Error('private close detail');
    } }; } } : stream,
    completion: async () => options.completion?.(sourceKind, requested) ?? ({ schema: 'amf.m4-preserved-replay-completion/v2', sourceKind,
      pauseCheckpoint: structuredClone(requested.pauseCheckpoint), endInclusive: requested.interval.endInclusive, chain: structuredClone(requested.interval.chain) }), }; };
  return { calls, queues, reader: { authority() { return structuredClone(attestation); }, open(request) { if (options.openThrow) throw Object.assign(new Error('private path'), { code: 'ENOENT' }); calls.open.push(structuredClone(request)); return openResult(request.sourceKind, request); },
    openPositions(request) { calls.positions.push(structuredClone(request)); return openResult(request.sourceKind, request, request.positions); } } };
}
function decoder(options = {}) {
  const calls = []; return { calls, decoder: { index(input) {
    calls.push({ type: 'index', input }); options.seenCiphertexts?.push(input.ciphertext); if (options.indexThrow) throw new Error('private decoder detail');
    const item = { schema: 'amf.m4-preserved-observation-index/v1', authorityDigest: input.authorityDigest, sourceKind: input.sourceKind, position: input.position,
      legacyEventId: input.legacyEventId, envelopeDigest: input.envelopeDigest, logicalMessageId: logical('a'), logicalMessageAliases: [], sessionId: 'session',
      projectionDigest: sha('projection-a'), projectionDigests: [{ logicalMessageId: logical('a'), projectionDigest: sha('projection-a') }], normalizationDigest: sha('normal'), sourceOccurredAt: '2026-07-22T00:00:00Z', authoritativeDeletion: false };
    return options.index?.(item, input) ?? item;
  }, materialize(input, request) { calls.push({ type: 'materialize', input, request }); return { eventId: input.legacyEventId, sessionId: 'session', sourceTag: request.sourceTag,
    migrationSequence: request.migrationSequence, projection: { eventId: input.legacyEventId }, visibleText: 'private decoder result' }; } } };
}
function prepare(records, options = {}) { const fakeReader = reader(records, options); const fakeDecoder = decoder(options); return prepareM4PreservedUnifiedIndex({ authority: fabricAuthority,
  reader: fakeReader.reader, decoder: fakeDecoder.decoder, sourceTag: `migration:${'a'.repeat(64)}`, maxEntries: options.maxEntries, maxBytes: options.maxBytes }).then(value => ({ ...value, readerCalls: fakeReader.calls, decoderCalls: fakeDecoder.calls, queues: fakeReader.queues })); }

test('attests empty complete queues without exposing ciphertext', async () => {
  const prepared = await prepare({});
  assert.deepEqual(prepared.indexes['preserved-outbox'].entries, []); assert.deepEqual(prepared.indexes['preserved-deadletter'].entries, []);
  assert.equal(prepared.totalEntries, 0); assert.equal(JSON.stringify(prepared.indexes).includes('private-'), false);
  assert.deepEqual(prepared.readerCalls.open.map(item => item.sourceKind), ['outbox', 'deadletter']);
});

test('snapshots injected methods and source tag before later caller mutation', async () => {
  const fakeReader = reader({ outbox: [raw('outbox', 1, 'a')] }); const fakeDecoder = decoder();
  const reads = { authority: 0, open: 0, openPositions: 0, index: 0, materialize: 0 };
  const wrappedReader = {}; const wrappedDecoder = {};
  for (const name of ['authority', 'open', 'openPositions']) Object.defineProperty(wrappedReader, name, { get() { reads[name] += 1; return fakeReader.reader[name]; } });
  for (const name of ['index', 'materialize']) Object.defineProperty(wrappedDecoder, name, { get() { reads[name] += 1; return fakeDecoder.decoder[name]; } });
  const input = { authority: fabricAuthority, reader: wrappedReader, decoder: wrappedDecoder,
    sourceTag: `migration:${'a'.repeat(64)}` };
  const prepared = await prepareM4PreservedUnifiedIndex(input); input.sourceTag = `migration:${'b'.repeat(64)}`;
  const entry = prepared.indexes['preserved-outbox'].entries[0];
  await prepared.materializers['preserved-outbox']({ authorityDigest: fabricAuthority.authorityDigest,
    canonicalLogicalMessageId: logical('a'), migrationSequence: 1, legacyEventId: entry.legacyEventId,
    projectionDigest: entry.projectionDigests[0].projectionDigest, origin: 'preserved-outbox', position: 1,
    recordDigest: entry.recordDigest });
  assert.deepEqual(reads, { authority: 1, open: 1, openPositions: 1, index: 1, materialize: 1 });
  assert.equal(fakeDecoder.calls.at(-1).request.sourceTag, `migration:${'a'.repeat(64)}`);
});

test('rejects completion drift and keeps errors content-free', async () => {
  await assert.rejects(() => prepare({ outbox: [raw('outbox', 1, 'a', 'do-not-leak')] }, { completion: (kind, request) => ({ schema: 'amf.m4-preserved-replay-completion/v2', sourceKind: kind,
    pauseCheckpoint: request.pauseCheckpoint, endInclusive: request.interval.endInclusive + 1, chain: request.interval.chain }) }), error => error.code === 'm4_preserved_unified_completion_invalid' && !error.message.includes('do-not-leak'));
});

test('normalizes close failures and rejects non-sequential attested enumeration', async () => {
  await assert.rejects(() => prepare({}, { closeThrow: true }), { code: 'm4_preserved_unified_reader_close_failed' });
  await assert.rejects(() => prepare({}, { closeThrow: 'hostile' }), { code: 'm4_preserved_unified_reader_close_failed' });
  await assert.rejects(() => prepare({ outbox: [raw('outbox', 2, 'a')] }), { code: 'm4_preserved_unified_reader_invalid' });
});

test('wipes invalid and trailing yielded ciphertext and normalizes foreign reader codes', async () => {
  const seenYielded = [];
  await assert.rejects(() => prepare({ outbox: [raw('outbox', 1, 'a', 'malformed-step')] }, { malformedStep: true, seenYielded }), { code: 'm4_preserved_unified_reader_invalid' });
  assert.equal(seenYielded[0].every(byte => byte === 0), true);
  await assert.rejects(() => prepare({ outbox: [{ ...raw('outbox', 1, 'a', 'invalid-cipher'), position: 0 }] }, { seenYielded }), { code: 'm4_preserved_unified_record_invalid' });
  assert.equal(seenYielded[0].every(byte => byte === 0), true);
  await assert.rejects(() => prepare({}, { openThrow: true }), { code: 'm4_preserved_unified_reader_invalid' });
  const trailing = raw('outbox', 2, 'b', 'trailing-cipher'); const setup = await prepare({ outbox: [raw('outbox', 1, 'a')] }, { trailing, seenYielded }); const entry = setup.indexes['preserved-outbox'].entries[0];
  await assert.rejects(() => setup.materializers['preserved-outbox']({ authorityDigest: fabricAuthority.authorityDigest, canonicalLogicalMessageId: logical('a'), migrationSequence: 1, legacyEventId: entry.legacyEventId, projectionDigest: entry.projectionDigests[0].projectionDigest, origin: 'preserved-outbox', position: 1, recordDigest: entry.recordDigest }), { code: 'm4_preserved_unified_materialization_mismatch' });
  assert.equal(seenYielded.at(-1).every(byte => byte === 0), true);
});

test('normalizes hostile top-level input traps', async () => {
  const hostile = new Proxy({}, { getPrototypeOf() { throw new Error('private input detail'); } });
  await assert.rejects(() => prepareM4PreservedUnifiedIndex(hostile), { code: 'm4_preserved_unified_dependency_invalid' });
});

test('rejects position response drift and inconsistent primary digest mapping', async () => {
  const setup = await prepare({ outbox: [raw('outbox', 1, 'a')] }, { positionsDrift: true }); const entry = setup.indexes['preserved-outbox'].entries[0];
  await assert.rejects(() => setup.materializers['preserved-outbox']({ authorityDigest: fabricAuthority.authorityDigest, canonicalLogicalMessageId: logical('a'), migrationSequence: 1, legacyEventId: entry.legacyEventId, projectionDigest: entry.projectionDigests[0].projectionDigest, origin: 'preserved-outbox', position: 1, recordDigest: entry.recordDigest }), { code: 'm4_preserved_unified_materialization_invalid' });
  await assert.rejects(() => prepare({ outbox: [raw('outbox', 1, 'a')] }, { index: item => ({ ...item, projectionDigest: sha('wrong') }) }), { code: 'm4_preserved_unified_decoder_invalid' });
});

test('enforces total bounds and wipes ciphertext after decoder failure', async () => {
  const one = raw('outbox', 1, 'a', 'wipe-on-failure');
  const seenCiphertexts = [];
  await assert.rejects(() => prepare({ outbox: [one] }, { indexThrow: true, seenCiphertexts }), { code: 'm4_preserved_unified_decoder_invalid' });
  assert.equal(seenCiphertexts[0].every(byte => byte === 0), true);
  const two = raw('outbox', 2, 'b');
  await assert.rejects(() => prepare({ outbox: [one, two] }, { maxEntries: 1, maxBytes: 1024 }), { code: 'm4_preserved_unified_bound_invalid' });
  assert.equal(one.ciphertext.every(byte => byte !== 0), true, 'fake reader retains its own source buffer');
});

test('reopens the exact pinned position, verifies record digest, and sends only the decoder request', async () => {
  const prepared = await prepare({ outbox: [raw('outbox', 1, 'a')] }); const entry = prepared.indexes['preserved-outbox'].entries[0];
  const value = await prepared.materializers['preserved-outbox']({ authorityDigest: fabricAuthority.authorityDigest, canonicalLogicalMessageId: logical('a'), migrationSequence: 7,
    legacyEventId: entry.legacyEventId, projectionDigest: entry.projectionDigests[0].projectionDigest, origin: 'preserved-outbox', position: 1, recordDigest: entry.recordDigest });
  assert.equal(value.visibleText, 'private decoder result'); assert.deepEqual(prepared.readerCalls.positions[0].positions, [1]);
  assert.deepEqual(prepared.decoderCalls.find(call => call.type === 'materialize').request, { logicalMessageId: logical('a'), sourceTag: `migration:${'a'.repeat(64)}`, migrationSequence: 7 });
  prepared.queues.outbox[0].envelopeDigest = sha('reader-drift');
  await assert.rejects(() => prepared.materializers['preserved-outbox']({ authorityDigest: fabricAuthority.authorityDigest, canonicalLogicalMessageId: logical('a'), migrationSequence: 1,
    legacyEventId: entry.legacyEventId, projectionDigest: entry.projectionDigests[0].projectionDigest, origin: 'preserved-outbox', position: 1, recordDigest: entry.recordDigest }), { code: 'm4_preserved_unified_materialization_mismatch' });
  await assert.rejects(() => prepared.materializers['preserved-outbox']({ authorityDigest: fabricAuthority.authorityDigest, canonicalLogicalMessageId: logical('a'), migrationSequence: 1,
    legacyEventId: entry.legacyEventId, projectionDigest: entry.projectionDigests[0].projectionDigest, origin: 'preserved-outbox', position: 1, recordDigest: sha('drift') }), { code: 'm4_preserved_unified_materialization_mismatch' });
});

test('rejects variant overflow and never puts plaintext in attestations', async () => {
  const variants = Array.from({ length: 129 }, (_, index) => ({ logicalMessageId: logical(index.toString(16)), projectionDigest: sha(`p-${index}`) }))
    .sort((a, b) => a.logicalMessageId.localeCompare(b.logicalMessageId));
  await assert.rejects(() => prepare({ outbox: [raw('outbox', 1, 'a', 'attestation-secret')] }, { index: item => ({ ...item, projectionDigests: variants }) }),
    { code: 'm4_preserved_unified_decoder_invalid' });
});
