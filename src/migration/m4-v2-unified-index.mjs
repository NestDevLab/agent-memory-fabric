import crypto from 'node:crypto';

import { canonicalJson } from '../ingest/transcripts/canonical.mjs';
import {
  RAW_EVENT_HTTP_MAX_BODY_BYTES,
  ciphertextContentId,
  ciphertextPayloadDigest,
  normalizeIngestKeyRing,
  validateClientCiphertext,
} from '../ingest/raw-event-contract.mjs';
import { buildM4V2LogicalGroup } from './m4-v2-catalog-groups.mjs';
import { readM4V2Observation } from './m4-v2-observation-reader.mjs';

export const M4_V2_UNIFIED_INDEX_MAX_ENTRIES = 1_000_000;
export const M4_V2_UNIFIED_INDEX_MAX_BYTES = 512 * 1024 * 1024 * 1024;
export const M4_V2_UNIFIED_INDEX_MAX_PROJECTION_VARIANTS = 128;

const DIGEST = /^sha256:[a-f0-9]{64}$/; const EVENT = /^evt_[a-f0-9]{64}$/; const LOGICAL = /^lmsg_[a-f0-9]{64}$/;
const SOURCE_TAG = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}:[a-f0-9]{64}$/;
const ENVELOPE_KEYS = ['schema', 'version', 'algorithm', 'eventId', 'sessionId', 'projectionSha256', 'payloadDigest',
  'sourceInstanceId', 'actorId', 'keyId', 'iv', 'tag', 'ciphertext'];
function fail(code) { const error = new Error(code); error.code = code; throw error; }
function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function exact(value, keys) { return plain(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)); }
function clone(value, code) { try { return structuredClone(value); } catch { fail(code); } }
function digest(value, code) { try { return `sha256:${crypto.createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`; } catch { fail(code); } }
function authority(value) {
  const safe = clone(value, 'm4_v2_unified_authority_invalid');
  try {
    if (!exact(safe, ['schema', 'authorityDigest']) || safe.schema !== 'amf.m4-group-replay-authority/v1' || !DIGEST.test(safe.authorityDigest)) fail('m4_v2_unified_authority_invalid');
    return safe;
  } catch { fail('m4_v2_unified_authority_invalid'); }
}
function bound(value, minimum, maximum) { if (!Number.isSafeInteger(value) || value < minimum || value > maximum) fail('m4_v2_unified_bound_invalid'); return value; }
function variants(row, code = 'm4_v2_unified_catalog_invalid') {
  try {
    const projection = row.projection;
    const all = [{ logicalMessageId: projection.logicalMessageId, keyVersion: projection.keyVersion }, ...projection.logicalMessageAliases];
    if (all.length < 1 || all.length > M4_V2_UNIFIED_INDEX_MAX_PROJECTION_VARIANTS
      || new Set(all.map(item => item.logicalMessageId)).size !== all.length) fail(code);
    return all.map(item => ({ logicalMessageId: item.logicalMessageId, projectionDigest: digest({ ...projection,
      logicalMessageId: item.logicalMessageId, keyVersion: item.keyVersion,
      logicalMessageAliases: all.filter(alias => alias.logicalMessageId !== item.logicalMessageId)
        .sort((a, b) => a.keyVersion.localeCompare(b.keyVersion) || a.logicalMessageId.localeCompare(b.logicalMessageId)) }, code) }))
      .sort((a, b) => a.logicalMessageId.localeCompare(b.logicalMessageId));
  } catch { fail(code); }
}
function binding(authorityDigest, row, envelope, code) {
  return digest({ schema: 'amf.m4-v2-unified-record/v1', authorityDigest, catalogRow: row, envelope }, code);
}
function snapshotEnvelope(value, maxCiphertextBytes) {
  let safe;
  try {
    if (!plain(value) || Object.keys(value).length !== ENVELOPE_KEYS.length || ENVELOPE_KEYS.some(key => !Object.hasOwn(value, key))) fail('m4_v2_unified_envelope_invalid');
    safe = Object.fromEntries(ENVELOPE_KEYS.map(key => [key, value[key]]));
    if (typeof safe.ciphertext !== 'string') fail('m4_v2_unified_envelope_invalid');
  } catch { fail('m4_v2_unified_envelope_invalid'); }
  if (safe.ciphertext.length > 4 * Math.ceil(maxCiphertextBytes / 3)) fail('m4_v2_unified_bound_invalid');
  return safe;
}
function ciphertextBytes(envelope, maxCiphertextBytes) {
  let encoded;
  try {
    if (!plain(envelope)) fail('m4_v2_unified_envelope_invalid');
    encoded = envelope.ciphertext; if (typeof encoded !== 'string') fail('m4_v2_unified_envelope_invalid');
  } catch { fail('m4_v2_unified_envelope_invalid'); }
  const maximumEncodedLength = 4 * Math.ceil(maxCiphertextBytes / 3);
  if (encoded.length > maximumEncodedLength) fail('m4_v2_unified_bound_invalid');
  let decoded; try { decoded = Buffer.from(encoded, 'base64'); } catch { fail('m4_v2_unified_envelope_invalid'); }
  if (decoded.length < 1 || decoded.toString('base64') !== encoded) fail('m4_v2_unified_envelope_invalid');
  if (decoded.length > maxCiphertextBytes) fail('m4_v2_unified_bound_invalid');
  return decoded.length;
}
function pageResult(value, pageLimit) {
  try {
    if (!plain(value) || Object.keys(value).length !== 2 || !Object.hasOwn(value, 'items') || !Object.hasOwn(value, 'next')) fail('m4_v2_unified_catalog_invalid');
    const items = value.items; const next = value.next;
    if (!Array.isArray(items) || items.length > pageLimit
      || (next !== null && (typeof next !== 'string' || !LOGICAL.test(next) || items.length !== pageLimit))) fail('m4_v2_unified_catalog_invalid');
    return { items: clone(items, 'm4_v2_unified_catalog_invalid'), next };
  } catch { fail('m4_v2_unified_catalog_invalid'); }
}

export async function prepareM4V2UnifiedIndex(input = {}) {
  try { if (!plain(input) || Object.keys(input).some(key => !['authority', 'catalog', 'rawStore', 'ingestKeys', 'verifyCatalogBinding', 'auditDecrypt', 'pageLimit', 'maxEntries', 'maxBytes', 'maxCiphertextBytes', 'readObservation'].includes(key))) fail('m4_v2_unified_dependency_invalid'); } catch { fail('m4_v2_unified_dependency_invalid'); }
  let rawAuthority; let catalog; let rawStore; let ingestKeys; let verifyCatalogBinding; let auditDecrypt; let list; let get; let read; let rawPageLimit; let rawMaxEntries; let rawMaxBytes; let rawMaxCiphertextBytes;
  try { rawAuthority = input.authority; catalog = input.catalog; rawStore = input.rawStore; ingestKeys = clone(input.ingestKeys, 'm4_v2_unified_dependency_invalid'); verifyCatalogBinding = input.verifyCatalogBinding; auditDecrypt = input.auditDecrypt; rawPageLimit = input.pageLimit; rawMaxEntries = input.maxEntries; rawMaxBytes = input.maxBytes; rawMaxCiphertextBytes = input.maxCiphertextBytes; list = catalog?.listM4V2LogicalGroups; get = rawStore?.getClientCiphertext; read = input.readObservation ?? readM4V2Observation; } catch { fail('m4_v2_unified_dependency_invalid'); }
  const safeAuthority = authority(rawAuthority);
  if (catalog === null || typeof catalog !== 'object' || rawStore === null || typeof rawStore !== 'object' || typeof list !== 'function' || typeof get !== 'function' || typeof read !== 'function' || typeof verifyCatalogBinding !== 'function' || typeof auditDecrypt !== 'function') fail('m4_v2_unified_dependency_invalid');
  let normalizedKeys; try { normalizedKeys = normalizeIngestKeyRing(ingestKeys); } catch { fail('m4_v2_unified_dependency_invalid'); }
  const pageLimit = bound(rawPageLimit ?? 100, 1, 100);
  const maxEntries = bound(rawMaxEntries ?? M4_V2_UNIFIED_INDEX_MAX_ENTRIES, 1, M4_V2_UNIFIED_INDEX_MAX_ENTRIES);
  const maxBytes = bound(rawMaxBytes ?? M4_V2_UNIFIED_INDEX_MAX_BYTES, 1, M4_V2_UNIFIED_INDEX_MAX_BYTES);
  const maxCiphertextBytes = bound(rawMaxCiphertextBytes ?? RAW_EVENT_HTTP_MAX_BODY_BYTES, 1_024, RAW_EVENT_HTTP_MAX_BODY_BYTES);
  async function scan({ collectEntries = false, capturePosition = null } = {}) {
    const entries = []; const seenEvents = new Set(); let captured = null; let after = null; let totalBytes = 0; let totalEntries = 0;
    let archiveDigest = digest({ schema: 'amf.m4-v2-unified-index-chain/v1', authorityDigest: safeAuthority.authorityDigest,
      position: 0, previous: null }, 'm4_v2_unified_catalog_invalid');
    for (;;) {
      let page; try { page = pageResult(await list.call(catalog, { after, limit: pageLimit }), pageLimit); } catch { fail('m4_v2_unified_catalog_invalid'); }
      if (page.items.length === 0) { if (page.next !== null) fail('m4_v2_unified_catalog_invalid'); break; }
      let last = after;
      for (const candidate of page.items) {
        let group; try { group = buildM4V2LogicalGroup(candidate.logical, candidate.observations); } catch { fail('m4_v2_unified_catalog_invalid'); }
        if (last !== null && group.logical.logicalMessageId <= last) fail('m4_v2_unified_catalog_invalid'); last = group.logical.logicalMessageId;
        for (const row of group.observations) {
          let rawEnvelope; try { rawEnvelope = await get.call(rawStore, row.contentId); } catch { fail('m4_v2_unified_envelope_invalid'); }
          const envelope = snapshotEnvelope(rawEnvelope, maxCiphertextBytes);
          const bytes = ciphertextBytes(envelope, maxCiphertextBytes); totalBytes += bytes; totalEntries += 1;
          if (totalEntries > maxEntries || totalBytes > maxBytes) fail('m4_v2_unified_bound_invalid');
          if (seenEvents.has(row.eventId)) fail('m4_v2_unified_catalog_invalid'); seenEvents.add(row.eventId);
          try {
            validateClientCiphertext({ actorId: envelope.actorId, sourceInstanceId: envelope.sourceInstanceId,
              projection: row.projection, envelope }, { allowedKeyIds: new Set(normalizedKeys.keys.keys()), authorizations: normalizedKeys.authorizations });
            if (ciphertextContentId(envelope) !== row.contentId || ciphertextPayloadDigest(envelope) !== row.payloadDigest) fail('m4_v2_unified_envelope_invalid');
          } catch { fail('m4_v2_unified_envelope_invalid'); }
          const recordDigest = binding(safeAuthority.authorityDigest, row, envelope, 'm4_v2_unified_envelope_invalid');
          const projectionDigests = variants(row);
          archiveDigest = digest({ schema: 'amf.m4-v2-unified-index-chain/v1', authorityDigest: safeAuthority.authorityDigest,
            position: totalEntries, previous: archiveDigest, legacyEventId: row.eventId, recordDigest }, 'm4_v2_unified_catalog_invalid');
          if (collectEntries) entries.push({ origin: 'v2-archive', position: totalEntries, legacyEventId: row.eventId,
            recordDigest, projectionDigests });
          if (capturePosition === totalEntries) captured = { row: clone(row, 'm4_v2_unified_catalog_invalid'),
            envelope: clone(envelope, 'm4_v2_unified_envelope_invalid'), recordDigest, projectionDigests };
        }
      }
      if (page.next === null) break; if (page.next !== last) fail('m4_v2_unified_catalog_invalid'); after = page.next;
    }
    return { archiveDigest, captured, entries, totalBytes, totalEntries };
  }
  const scanned = await scan({ collectEntries: true }); const { entries } = scanned;
  const index = Object.freeze({ schema: 'amf.m4-unified-logical-index/v1', authorityDigest: safeAuthority.authorityDigest, origin: 'v2-archive', complete: true,
    entries: Object.freeze(entries.map(entry => Object.freeze({ ...entry, projectionDigests: Object.freeze(entry.projectionDigests.map(item => Object.freeze({ ...item }))) }))) });
  async function materializer(locator) {
    const safeLocator = clone(locator, 'm4_v2_unified_materialization_invalid');
    try {
      if (!exact(safeLocator, ['authorityDigest', 'canonicalLogicalMessageId', 'migrationSequence', 'legacyEventId', 'projectionDigest', 'origin', 'position', 'recordDigest'])
        || safeLocator.authorityDigest !== safeAuthority.authorityDigest || safeLocator.origin !== 'v2-archive'
        || !LOGICAL.test(safeLocator.canonicalLogicalMessageId) || !EVENT.test(safeLocator.legacyEventId)
        || !DIGEST.test(safeLocator.recordDigest) || !DIGEST.test(safeLocator.projectionDigest)
        || !Number.isSafeInteger(safeLocator.position) || safeLocator.position < 1
        || !Number.isSafeInteger(safeLocator.migrationSequence) || safeLocator.migrationSequence < 1) fail('m4_v2_unified_materialization_invalid');
    } catch { fail('m4_v2_unified_materialization_invalid'); }
    const current = await scan({ capturePosition: safeLocator.position }); const item = current.captured;
    if (current.archiveDigest !== scanned.archiveDigest || current.totalEntries !== scanned.totalEntries || current.totalBytes !== scanned.totalBytes
      || !item || item.row.eventId !== safeLocator.legacyEventId || item.recordDigest !== safeLocator.recordDigest) fail('m4_v2_unified_materialization_mismatch');
    const signed = item.projectionDigests.find(value => value.logicalMessageId === safeLocator.canonicalLogicalMessageId);
    if (!signed || signed.projectionDigest !== safeLocator.projectionDigest) fail('m4_v2_unified_materialization_mismatch');
    const selectedRow = { ...item.row, logicalMessageId: safeLocator.canonicalLogicalMessageId };
    let observation; try { observation = clone(await read.call(null, { catalogRow: selectedRow, envelope: item.envelope, ingestKeys,
      migrationSequence: safeLocator.migrationSequence, verifyCatalogBinding, auditDecrypt, maxCiphertextBytes }),
    'm4_v2_unified_materialization_invalid'); } catch { fail('m4_v2_unified_materialization_invalid'); }
    try { if (!exact(observation, ['eventId', 'sessionId', 'sourceTag', 'migrationSequence', 'projection', 'visibleText'])
      || observation.eventId !== safeLocator.legacyEventId || typeof observation.sourceTag !== 'string' || !SOURCE_TAG.test(observation.sourceTag)
      || observation.migrationSequence !== safeLocator.migrationSequence || !plain(observation.projection)
      || observation.projection.eventId !== safeLocator.legacyEventId) fail('m4_v2_unified_materialization_invalid'); } catch { fail('m4_v2_unified_materialization_invalid'); }
    if (observation.projection.logicalMessageId !== safeLocator.canonicalLogicalMessageId) fail('m4_v2_unified_materialization_mismatch');
    if (digest(observation.projection, 'm4_v2_unified_materialization_mismatch') !== safeLocator.projectionDigest) fail('m4_v2_unified_materialization_mismatch');
    return clone(observation, 'm4_v2_unified_materialization_invalid');
  }
  return Object.freeze({ index, materializer, totalEntries: scanned.totalEntries, totalBytes: scanned.totalBytes });
}
