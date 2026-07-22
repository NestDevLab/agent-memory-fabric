import { canonicalJson } from '../ingest/transcripts/canonical.mjs';

/**
 * Fabric-side adapter for the preserved raw-queue reader.  The raw adapter owns
 * queue access and envelope decoding; this module only binds its attestations
 * into the M4 unified logical source contract.
 */
export const M4_PRESERVED_UNIFIED_INDEX_MAX_ENTRIES = 1_000_000;
export const M4_PRESERVED_UNIFIED_INDEX_MAX_BYTES = 512 * 1024 * 1024 * 1024;
export const M4_PRESERVED_UNIFIED_INDEX_MAX_PROJECTION_VARIANTS = 128;

const DIGEST = /^sha256:[a-f0-9]{64}$/;
const EVENT = /^evt_[a-f0-9]{64}$/;
const LOGICAL = /^lmsg_[a-f0-9]{64}$/;
const ID = /^[a-z][a-z0-9-]{2,79}$/;
const SOURCE_TAG = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}:[a-f0-9]{64}$/;
const ORIGINS = Object.freeze({ outbox: 'preserved-outbox', deadletter: 'preserved-deadletter' });

function fail(code) { const error = new Error(code); error.code = code; throw error; }
function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function exact(value, keys) { return plain(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)); }
function same(left, right) { try { return canonicalJson(left) === canonicalJson(right); } catch { return false; } }
function wipe(value) { if (Buffer.isBuffer(value)) value.fill(0); }
function wipeCandidate(value) { try { if (value !== null && typeof value === 'object') wipe(value.ciphertext); } catch { /* never replace the primary failure */ } }
function wipeIteratorValue(value) { try { wipeCandidate(value?.value); } catch { /* never replace the primary failure */ } }
function clone(value, code) { try { return structuredClone(value); } catch { fail(code); } }
function checkpoint(value) { return exact(value, ['id', 'digest']) && typeof value.id === 'string' && ID.test(value.id) && typeof value.digest === 'string' && DIGEST.test(value.digest); }
function authority(value) {
  try {
    if (!exact(value, ['schema', 'authorityDigest']) || value.schema !== 'amf.m4-group-replay-authority/v1' || !DIGEST.test(value.authorityDigest)) fail('m4_preserved_unified_authority_invalid');
    return clone(value, 'm4_preserved_unified_authority_invalid');
  } catch { fail('m4_preserved_unified_authority_invalid'); }
}
function sourceAuthority(value, sourceKind) {
  try {
    if (!exact(value, ['acknowledgements', 'sources']) || !checkpoint(value.acknowledgements) || !exact(value.sources, ['outbox', 'deadletter']) || !plain(value.sources[sourceKind])) fail('m4_preserved_unified_reader_authority_invalid');
    const source = value.sources[sourceKind];
    if (!exact(source, ['pauseCheckpoint', 'interval', 'initialCheckpoint']) || !checkpoint(source.pauseCheckpoint) || !checkpoint(source.initialCheckpoint) || !exact(source.interval, ['startExclusive', 'endInclusive', 'chain'])
      || source.interval.startExclusive !== 0
      || !Number.isSafeInteger(source.interval.endInclusive) || source.interval.endInclusive < source.interval.startExclusive
      || !checkpoint(source.interval.chain)) fail('m4_preserved_unified_reader_authority_invalid');
    return clone(source, 'm4_preserved_unified_reader_authority_invalid');
  } catch { fail('m4_preserved_unified_reader_authority_invalid'); }
}
function record(value, sourceKind) {
  try {
    if (!exact(value, ['sourceKind', 'position', 'legacyEventId', 'envelopeDigest', 'ciphertext']) || value.sourceKind !== sourceKind
      || !Number.isSafeInteger(value.position) || value.position < 1 || !EVENT.test(value.legacyEventId)
      || !DIGEST.test(value.envelopeDigest) || !Buffer.isBuffer(value.ciphertext) || value.ciphertext.length < 1) fail('m4_preserved_unified_record_invalid');
    return value;
  } catch { fail('m4_preserved_unified_record_invalid'); }
}
function projectionDigests(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > M4_PRESERVED_UNIFIED_INDEX_MAX_PROJECTION_VARIANTS
    || value.some(item => !exact(item, ['logicalMessageId', 'projectionDigest']) || !LOGICAL.test(item.logicalMessageId) || !DIGEST.test(item.projectionDigest))
    || new Set(value.map(item => item.logicalMessageId)).size !== value.length
    || !same(value, [...value].sort((a, b) => a.logicalMessageId.localeCompare(b.logicalMessageId)))) fail('m4_preserved_unified_decoder_invalid');
  return clone(value, 'm4_preserved_unified_decoder_invalid');
}
function indexed(value, authorityDigest, raw) {
  try {
    const keys = ['schema', 'authorityDigest', 'sourceKind', 'position', 'legacyEventId', 'envelopeDigest', 'logicalMessageId', 'logicalMessageAliases', 'sessionId', 'projectionDigest', 'projectionDigests', 'normalizationDigest', 'sourceOccurredAt', 'authoritativeDeletion'];
    if (!exact(value, keys) || value.schema !== 'amf.m4-preserved-observation-index/v1' || value.authorityDigest !== authorityDigest
      || value.sourceKind !== raw.sourceKind || value.position !== raw.position || value.legacyEventId !== raw.legacyEventId
      || value.envelopeDigest !== raw.envelopeDigest || !LOGICAL.test(value.logicalMessageId) || !DIGEST.test(value.projectionDigest)
      || !Array.isArray(value.logicalMessageAliases) || value.logicalMessageAliases.some(alias => !exact(alias, ['keyVersion', 'logicalMessageId'])
        || typeof alias.keyVersion !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(alias.keyVersion) || !LOGICAL.test(alias.logicalMessageId))
      || new Set(value.logicalMessageAliases.map(alias => alias.logicalMessageId)).size !== value.logicalMessageAliases.length
      || value.logicalMessageAliases.some(alias => alias.logicalMessageId === value.logicalMessageId)) fail('m4_preserved_unified_decoder_invalid');
    const values = projectionDigests(value.projectionDigests);
    const expected = new Set([value.logicalMessageId, ...value.logicalMessageAliases.map(alias => alias.logicalMessageId)]);
    const primary = values.find(item => item.logicalMessageId === value.logicalMessageId);
    if (primary?.projectionDigest !== value.projectionDigest || values.length !== expected.size || values.some(item => !expected.has(item.logicalMessageId))) fail('m4_preserved_unified_decoder_invalid');
    return values;
  } catch { fail('m4_preserved_unified_decoder_invalid'); }
}
function limits(value, maximum, code) { if (!Number.isSafeInteger(value) || value < 1 || value > maximum) fail(code); return value; }
function requestFor(sourceKind, source) { return { schema: 'amf.m4-preserved-replay-authority/v2', sourceKind,
  pauseCheckpoint: clone(source.pauseCheckpoint, 'm4_preserved_unified_reader_authority_invalid'), interval: clone(source.interval, 'm4_preserved_unified_reader_authority_invalid'), afterSequence: 0 }; }
function positionRequestFor(sourceKind, source, position) { return { schema: 'amf.m4-preserved-position-read/v1', sourceKind,
  pauseCheckpoint: clone(source.pauseCheckpoint, 'm4_preserved_unified_reader_authority_invalid'), interval: clone(source.interval, 'm4_preserved_unified_reader_authority_invalid'), positions: [position] }; }
function readerResult(value, schema, sourceKind, source, positions = null) {
  try {
    const keys = schema === 'amf.m4-preserved-position-reader/v1'
      ? ['schema', 'sourceKind', 'pauseCheckpoint', 'interval', 'positions', 'records', 'completion']
      : ['schema', 'sourceKind', 'pauseCheckpoint', 'interval', 'records', 'completion'];
    if (!exact(value, keys) || value.schema !== schema
      || value.sourceKind !== sourceKind || !same(value.pauseCheckpoint, source.pauseCheckpoint) || !same(value.interval, source.interval)
      || (positions !== null && (!same(value.positions, positions))) || typeof value.records?.[Symbol.asyncIterator] !== 'function' || typeof value.completion !== 'function') fail('m4_preserved_unified_reader_invalid');
    return value;
  } catch { fail('m4_preserved_unified_reader_invalid'); }
}
function iteratorFor(opened) {
  try { const iterator = opened.records[Symbol.asyncIterator](); if (iterator === null || typeof iterator !== 'object' || typeof iterator.next !== 'function') fail('m4_preserved_unified_reader_invalid'); return iterator; }
  catch { fail('m4_preserved_unified_reader_invalid'); }
}
async function next(iterator) {
  let value;
  try { value = await iterator.next(); } catch { fail('m4_preserved_unified_reader_invalid'); }
  try {
    if (!plain(value) || typeof value.done !== 'boolean' || (!value.done && !Object.hasOwn(value, 'value'))) fail('m4_preserved_unified_reader_invalid');
    return value;
  } catch { wipeIteratorValue(value); fail('m4_preserved_unified_reader_invalid'); }
}
async function close(iterator, primary) {
  try { if (typeof iterator?.return !== 'function') fail('m4_preserved_unified_reader_close_failed'); await iterator.return(); }
  catch { if (primary) return; fail('m4_preserved_unified_reader_close_failed'); }
}
async function completion(opened, sourceKind, source) {
  let value;
  try { value = await opened.completion(); } catch { fail('m4_preserved_unified_completion_invalid'); }
  if (!exact(value, ['schema', 'sourceKind', 'pauseCheckpoint', 'endInclusive', 'chain']) || value.schema !== 'amf.m4-preserved-replay-completion/v2'
    || value.sourceKind !== sourceKind || !same(value.pauseCheckpoint, source.pauseCheckpoint)
    || value.endInclusive !== source.interval.endInclusive || !same(value.chain, source.interval.chain)) fail('m4_preserved_unified_completion_invalid');
}
function minimal(value, legacyEventId, migrationSequence, sourceTag) {
  try {
    if (!exact(value, ['eventId', 'sessionId', 'sourceTag', 'migrationSequence', 'projection', 'visibleText']) || value.eventId !== legacyEventId
      || value.migrationSequence !== migrationSequence || value.sourceTag !== sourceTag || !plain(value.projection) || value.projection.eventId !== legacyEventId) fail('m4_preserved_unified_materialization_invalid');
    return clone(value, 'm4_preserved_unified_materialization_invalid');
  } catch { fail('m4_preserved_unified_materialization_invalid'); }
}

export async function prepareM4PreservedUnifiedIndex(input = {}) {
  try {
    if (!plain(input) || Object.keys(input).some(key => !['authority', 'reader', 'decoder', 'sourceTag', 'maxEntries', 'maxBytes'].includes(key))
      || !['authority', 'reader', 'decoder', 'sourceTag'].every(key => Object.hasOwn(input, key))) fail('m4_preserved_unified_dependency_invalid');
  } catch { fail('m4_preserved_unified_dependency_invalid'); }
  let rawAuthorityInput; let reader; let decoder; let sourceTag; let rawMaxEntries; let rawMaxBytes;
  let readAuthority; let open; let openPositions; let decodeIndex; let materialize;
  try {
    rawAuthorityInput = input.authority; reader = input.reader; decoder = input.decoder; sourceTag = input.sourceTag;
    rawMaxEntries = input.maxEntries; rawMaxBytes = input.maxBytes;
    readAuthority = reader?.authority; open = reader?.open; openPositions = reader?.openPositions;
    decodeIndex = decoder?.index; materialize = decoder?.materialize;
  } catch { fail('m4_preserved_unified_dependency_invalid'); }
  const safeAuthority = authority(rawAuthorityInput);
  if (reader === null || typeof reader !== 'object' || decoder === null || typeof decoder !== 'object'
    || typeof readAuthority !== 'function' || typeof open !== 'function' || typeof openPositions !== 'function'
    || typeof decodeIndex !== 'function' || typeof materialize !== 'function'
    || typeof sourceTag !== 'string' || !SOURCE_TAG.test(sourceTag)) fail('m4_preserved_unified_dependency_invalid');
  const maxEntries = limits(rawMaxEntries ?? M4_PRESERVED_UNIFIED_INDEX_MAX_ENTRIES, M4_PRESERVED_UNIFIED_INDEX_MAX_ENTRIES, 'm4_preserved_unified_bound_invalid');
  const maxBytes = limits(rawMaxBytes ?? M4_PRESERVED_UNIFIED_INDEX_MAX_BYTES, M4_PRESERVED_UNIFIED_INDEX_MAX_BYTES, 'm4_preserved_unified_bound_invalid');
  let rawAuthority; try { rawAuthority = await readAuthority.call(reader); } catch { fail('m4_preserved_unified_reader_authority_invalid'); }
  const sources = Object.fromEntries(Object.keys(ORIGINS).map(kind => [kind, sourceAuthority(rawAuthority, kind)]));
  let totalEntries = 0; let totalBytes = 0;
  const indexes = {};
  for (const sourceKind of Object.keys(ORIGINS)) {
    let opened; try { opened = readerResult(await open.call(reader, requestFor(sourceKind, sources[sourceKind])), 'amf.m4-preserved-replay-reader/v2', sourceKind, sources[sourceKind]); }
    catch { fail('m4_preserved_unified_reader_invalid'); }
    const iterator = iteratorFor(opened); const entries = []; let primary; let expectedPosition = 1;
    try {
      for (;;) {
        const step = await next(iterator); if (step.done) break; const candidate = step.value;
        try {
          const raw = record(candidate, sourceKind);
          if (raw.position !== expectedPosition) fail('m4_preserved_unified_reader_invalid');
          expectedPosition += 1;
          totalEntries += 1; totalBytes += raw.ciphertext.byteLength;
          if (totalEntries > maxEntries || totalBytes > maxBytes) fail('m4_preserved_unified_bound_invalid');
          let value;
          try { value = await decodeIndex.call(decoder, { authorityDigest: safeAuthority.authorityDigest, ...raw }); }
          catch { fail('m4_preserved_unified_decoder_invalid'); }
          entries.push({ origin: ORIGINS[sourceKind], position: raw.position, legacyEventId: raw.legacyEventId,
            recordDigest: raw.envelopeDigest, projectionDigests: indexed(value, safeAuthority.authorityDigest, raw) });
        } finally { wipeCandidate(candidate); }
      }
      if (expectedPosition - 1 !== sources[sourceKind].interval.endInclusive) fail('m4_preserved_unified_reader_invalid');
      await completion(opened, sourceKind, sources[sourceKind]);
    } catch (error) { primary = error; throw error; } finally { await close(iterator, primary); }
    indexes[ORIGINS[sourceKind]] = Object.freeze({ schema: 'amf.m4-unified-logical-index/v1', authorityDigest: safeAuthority.authorityDigest,
      origin: ORIGINS[sourceKind], complete: true, entries: Object.freeze(entries.map(item => Object.freeze({ ...item,
        projectionDigests: Object.freeze(item.projectionDigests.map(variant => Object.freeze({ ...variant }))) }))) });
  }
  const materializers = {};
  for (const [sourceKind, origin] of Object.entries(ORIGINS)) materializers[origin] = async locator => {
    if (!exact(locator, ['authorityDigest', 'canonicalLogicalMessageId', 'migrationSequence', 'legacyEventId', 'projectionDigest', 'origin', 'position', 'recordDigest'])
      || locator.authorityDigest !== safeAuthority.authorityDigest || locator.origin !== origin || !LOGICAL.test(locator.canonicalLogicalMessageId)
      || !Number.isSafeInteger(locator.migrationSequence) || locator.migrationSequence < 1 || !EVENT.test(locator.legacyEventId)
      || !Number.isSafeInteger(locator.position) || locator.position < 1 || !DIGEST.test(locator.recordDigest) || !DIGEST.test(locator.projectionDigest)) fail('m4_preserved_unified_materialization_invalid');
    let opened; try { opened = readerResult(await openPositions.call(reader, positionRequestFor(sourceKind, sources[sourceKind], locator.position)), 'amf.m4-preserved-position-reader/v1', sourceKind, sources[sourceKind], [locator.position]); }
    catch { fail('m4_preserved_unified_materialization_invalid'); }
    const iterator = iteratorFor(opened); let primary;
    try {
      const first = await next(iterator); if (first.done) fail('m4_preserved_unified_materialization_mismatch'); const candidate = first.value;
      try {
        const raw = record(candidate, sourceKind);
        if (raw.legacyEventId !== locator.legacyEventId || raw.envelopeDigest !== locator.recordDigest) fail('m4_preserved_unified_materialization_mismatch');
        let result;
        try { result = await materialize.call(decoder, { authorityDigest: safeAuthority.authorityDigest, ...raw }, { logicalMessageId: locator.canonicalLogicalMessageId,
          sourceTag, migrationSequence: locator.migrationSequence }); }
        catch { fail('m4_preserved_unified_materialization_invalid'); }
        const trailing = await next(iterator);
        try { if (!trailing.done) fail('m4_preserved_unified_materialization_mismatch'); }
        finally { if (!trailing.done) wipeCandidate(trailing.value); }
        await completion(opened, sourceKind, sources[sourceKind]); return minimal(result, locator.legacyEventId, locator.migrationSequence, sourceTag);
      } finally { wipeCandidate(candidate); }
    } catch (error) { primary = error; throw error; } finally { await close(iterator, primary); }
  };
  return Object.freeze({ indexes: Object.freeze(indexes), materializers: Object.freeze(materializers), totalEntries, totalBytes });
}
