import crypto from 'node:crypto';

import { canonicalJson } from '../ingest/transcripts/canonical.mjs';

export const M4_CATALOG_REFERENCE_SNAPSHOT_SCHEMA = 'amf.m4-catalog-reference-snapshot/v1';
export const M4_SELECTOR_SCOPE_SNAPSHOT_SCHEMA = 'amf.m4-selector-scope-snapshot/v1';

const KEY_SCHEMA = 'amf.migration-signing-key/v1';
const CATALOG_DOMAIN = 'amf.m4-catalog-reference-snapshot/v1/integrity';
const SCOPE_DOMAIN = 'amf.m4-selector-scope-snapshot/v1/integrity';
const ID = /^[a-z][a-z0-9-]{2,79}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const SIGNATURE = /^[A-Za-z0-9_-]{43,86}$/;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const SOURCE = /^src_[a-z0-9][a-z0-9_-]{7,127}$/;
const REVISION = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const TARGET_TYPES = new Set(['transcript-row', 'transcript-blob']);
const MAX_TARGETS = 100_000;
const MAX_REFERENCES = 1_000_000;
const MAX_SELECTORS = 256;
const MAX_AUTHORITY_WINDOW_NS = 7n * 24n * 60n * 60n * 1_000_000_000n;

function fail(code) { const error = new Error(code); error.code = code; throw error; }
function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function snapshot(value, keys, code) {
  try {
    if (!plain(value) || Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key))) fail(code);
    return Object.fromEntries(keys.map(key => [key, value[key]]));
  } catch (error) { if (error?.code === code) throw error; fail(code); }
}
function checkpoint(value, code) {
  const item = snapshot(value, ['id', 'digest'], code);
  if (typeof item.id !== 'string' || !ID.test(item.id) || typeof item.digest !== 'string' || !DIGEST.test(item.digest)) fail(code);
  return item;
}
function keyDocument(value, code) {
  const item = snapshot(value, ['schema', 'keyId', 'key'], code);
  if (item.schema !== KEY_SCHEMA || typeof item.keyId !== 'string' || !ID.test(item.keyId) || typeof item.key !== 'string' || !BASE64.test(item.key)) fail(code);
  const key = Buffer.from(item.key, 'base64');
  if (key.length < 32 || key.length > 64 || key.toString('base64') !== item.key) { key.fill(0); fail(code); }
  return { keyId: item.keyId, key };
}
function sha(value) { return `sha256:${crypto.createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`; }
function signatureFor(domain, payloadDigest, loadedKey) {
  return crypto.createHmac('sha256', loadedKey.key).update(canonicalJson([domain, payloadDigest, loadedKey.keyId]), 'utf8').digest('base64url');
}
function timestamp(value, code) {
  if (typeof value !== 'string') fail(code);
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$/.exec(value);
  if (!match) fail(code);
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number);
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (month < 1 || month > 12 || day < 1 || day > days[month - 1] || hour > 23 || minute > 59 || second > 59) fail(code);
  return value;
}
function timeKey(value) {
  const [whole, fraction = ''] = value.slice(0, -1).split('.');
  return `${whole}.${fraction.padEnd(9, '0')}Z`;
}
function timeNanoseconds(value) {
  const [whole, fraction = ''] = value.slice(0, -1).split('.');
  return BigInt(Date.parse(`${whole}Z`)) * 1_000_000n + BigInt(fraction.padEnd(9, '0') || '0');
}
function compareText(left, right) { return left < right ? -1 : left > right ? 1 : 0; }
function validWindow(start, end) {
  return timeKey(start) <= timeKey(end) && timeNanoseconds(end) - timeNanoseconds(start) <= MAX_AUTHORITY_WINDOW_NS;
}
export function timestampWithin(value, start, end) {
  const key = timeKey(timestamp(value, 'm4_authority_snapshot_time_invalid'));
  return key >= timeKey(timestamp(start, 'm4_authority_snapshot_time_invalid')) && key <= timeKey(timestamp(end, 'm4_authority_snapshot_time_invalid'));
}
function selector(value, code) {
  const item = snapshot(value, ['sourceInstanceId', 'contentClass'], code);
  if (typeof item.sourceInstanceId !== 'string' || !SOURCE.test(item.sourceInstanceId) || item.contentClass !== 'conversation') fail(code);
  return item;
}
function selectors(value, code, allowEmpty = false) {
  if (!Array.isArray(value) || value.length > MAX_SELECTORS || (!allowEmpty && value.length < 1)) fail(code);
  const result = value.map(item => selector(item, code));
  for (let index = 1; index < result.length; index += 1) if (result[index - 1].sourceInstanceId >= result[index].sourceInstanceId) fail(code);
  return result;
}
function reference(value, code) { return checkpoint(value, code); }
function catalogObject(value, code, requireSorted = true) {
  const item = snapshot(value, ['id', 'digest', 'objectType', 'sourceInstanceId', 'contentClass', 'references'], code);
  if (typeof item.id !== 'string' || !ID.test(item.id) || typeof item.digest !== 'string' || !DIGEST.test(item.digest)
    || !TARGET_TYPES.has(item.objectType) || typeof item.sourceInstanceId !== 'string' || !SOURCE.test(item.sourceInstanceId)
    || item.contentClass !== 'conversation' || !Array.isArray(item.references) || item.references.length > MAX_REFERENCES) fail(code);
  const references = item.references.map(entry => reference(entry, code));
  if (requireSorted) for (let index = 1; index < references.length; index += 1) if (references[index - 1].id >= references[index].id) fail(code);
  if (new Set(references.map(entry => entry.digest)).size !== references.length) fail(code);
  return { ...item, references };
}
function catalogObjects(value, code) {
  if (!Array.isArray(value) || value.length < 1 || value.length > MAX_TARGETS) fail(code);
  const result = value.map(entry => catalogObject(entry, code));
  const digests = new Set(); let referenceCount = 0;
  for (let index = 0; index < result.length; index += 1) {
    if ((index > 0 && result[index - 1].id >= result[index].id) || digests.has(result[index].digest)) fail(code);
    digests.add(result[index].digest); referenceCount += result[index].references.length;
    if (referenceCount > MAX_REFERENCES) fail(code);
  }
  return result;
}
function eligibleTargets(objects) {
  return objects.filter(entry => entry.references.length === 0).map(({ references, ...entry }) => ({ ...entry, referenceCount: references.length }));
}
function selectorCountsFor(targets) {
  const counts = new Map();
  for (const target of targets) counts.set(target.sourceInstanceId, (counts.get(target.sourceInstanceId) || 0) + 1);
  return [...counts].sort(([left], [right]) => compareText(left, right)).map(([sourceInstanceId, eligibleCount]) => ({ sourceInstanceId, contentClass: 'conversation', eligibleCount }));
}
function catalogPayload(value, code) {
  const item = snapshot(value, ['schema', 'snapshotId', 'revision', 'catalogRevision', 'observedAt', 'validThrough', 'scanState', 'objects', 'scannedObjectCount', 'scannedReferenceCount', 'scanDigest', 'eligibleTargets', 'selectorCounts'], code);
  if (item.schema !== M4_CATALOG_REFERENCE_SNAPSHOT_SCHEMA || typeof item.snapshotId !== 'string' || !ID.test(item.snapshotId)
    || !Number.isSafeInteger(item.revision) || item.revision < 1 || item.scanState !== 'complete') fail(code);
  const observedAt = timestamp(item.observedAt, code); const validThrough = timestamp(item.validThrough, code);
  if (!validWindow(observedAt, validThrough)) fail(code);
  const objects = catalogObjects(item.objects, code); const derivedTargets = eligibleTargets(objects); const derivedCounts = selectorCountsFor(derivedTargets);
  if (item.scannedObjectCount !== objects.length || item.scannedReferenceCount !== objects.reduce((sum, entry) => sum + entry.references.length, 0)
    || item.scanDigest !== sha(objects) || canonicalJson(item.eligibleTargets) !== canonicalJson(derivedTargets)
    || canonicalJson(item.selectorCounts) !== canonicalJson(derivedCounts)) fail(code);
  return { schema: M4_CATALOG_REFERENCE_SNAPSHOT_SCHEMA, snapshotId: item.snapshotId, revision: item.revision,
    catalogRevision: checkpoint(item.catalogRevision, code), observedAt, validThrough, scanState: 'complete', objects, scannedObjectCount: item.scannedObjectCount,
    scannedReferenceCount: item.scannedReferenceCount, scanDigest: item.scanDigest, eligibleTargets: derivedTargets, selectorCounts: derivedCounts };
}
function scopePayload(value, code) {
  const item = snapshot(value, ['schema', 'snapshotId', 'revision', 'policyRevision', 'policyDigest', 'observedAt', 'validThrough', 'selectors', 'selectorDigest'], code);
  if (item.schema !== M4_SELECTOR_SCOPE_SNAPSHOT_SCHEMA || typeof item.snapshotId !== 'string' || !ID.test(item.snapshotId)
    || !Number.isSafeInteger(item.revision) || item.revision < 1 || typeof item.policyRevision !== 'string' || !REVISION.test(item.policyRevision)
    || typeof item.policyDigest !== 'string' || !DIGEST.test(item.policyDigest)) fail(code);
  const observedAt = timestamp(item.observedAt, code); const validThrough = timestamp(item.validThrough, code);
  if (!validWindow(observedAt, validThrough)) fail(code);
  const selected = selectors(item.selectors, code);
  if (item.selectorDigest !== sha(selected)) fail(code);
  return { schema: M4_SELECTOR_SCOPE_SNAPSHOT_SCHEMA, snapshotId: item.snapshotId, revision: item.revision,
    policyRevision: item.policyRevision, policyDigest: item.policyDigest, observedAt, validThrough, selectors: selected, selectorDigest: item.selectorDigest };
}
function integrity(value, code) {
  const item = snapshot(value, ['algorithm', 'keyId', 'payloadDigest', 'signature'], code);
  if (item.algorithm !== 'hmac-sha256' || typeof item.keyId !== 'string' || !ID.test(item.keyId) || typeof item.payloadDigest !== 'string'
    || !DIGEST.test(item.payloadDigest) || typeof item.signature !== 'string' || !SIGNATURE.test(item.signature)) fail(code);
  return item;
}
async function collect(source, normalizer, code, max) {
  if (!source || typeof source[Symbol.asyncIterator] !== 'function') fail(code);
  const result = [];
  try { for await (const entry of source) { if (result.length >= max) fail(code); result.push(normalizer(entry, code)); } }
  catch (error) { if (error?.code === code) throw error; fail(code); }
  return result;
}

export async function collectM4CatalogReferenceSnapshot(value) {
  const input = value;
  if (!plain(input)) fail('m4_catalog_reference_snapshot_input_invalid');
  const keys = ['snapshotId', 'revision', 'catalogRevision', 'observedAt', 'validThrough', 'catalogSource', 'keyDocument'];
  if (Object.keys(input).length !== keys.length || keys.some(key => !Object.hasOwn(input, key))) fail('m4_catalog_reference_snapshot_input_invalid');
  const objects = await collect(input.catalogSource, (entry, code) => catalogObject(entry, code, false), 'm4_catalog_reference_snapshot_input_invalid', MAX_TARGETS);
  objects.sort((left, right) => compareText(left.id, right.id));
  for (const object of objects) object.references.sort((left, right) => compareText(left.id, right.id));
  const targets = eligibleTargets(objects); const counts = selectorCountsFor(targets);
  const body = catalogPayload({ schema: M4_CATALOG_REFERENCE_SNAPSHOT_SCHEMA, snapshotId: input.snapshotId, revision: input.revision,
    catalogRevision: input.catalogRevision, observedAt: input.observedAt, validThrough: input.validThrough, scanState: 'complete', objects,
    scannedObjectCount: objects.length, scannedReferenceCount: objects.reduce((sum, entry) => sum + entry.references.length, 0),
    scanDigest: sha(objects), eligibleTargets: targets, selectorCounts: counts }, 'm4_catalog_reference_snapshot_input_invalid');
  const loaded = keyDocument(input.keyDocument, 'm4_catalog_reference_snapshot_key_invalid');
  try { const payloadDigest = sha(body); return structuredClone({ ...body, integrity: { algorithm: 'hmac-sha256', keyId: loaded.keyId,
    payloadDigest, signature: signatureFor(CATALOG_DOMAIN, payloadDigest, loaded) } }); } finally { loaded.key.fill(0); }
}

export function verifyM4CatalogReferenceSnapshot(value, signingKeyDocument) {
  let item;
  try { item = snapshot(structuredClone(value), ['schema', 'snapshotId', 'revision', 'catalogRevision', 'observedAt', 'validThrough', 'scanState', 'objects', 'scannedObjectCount', 'scannedReferenceCount', 'scanDigest', 'eligibleTargets', 'selectorCounts', 'integrity'], 'm4_catalog_reference_snapshot_invalid'); }
  catch (error) { if (typeof error?.code === 'string' && error.code.startsWith('m4_')) throw error; fail('m4_catalog_reference_snapshot_invalid'); }
  const { integrity: rawIntegrity, ...rawBody } = item;
  const body = catalogPayload(rawBody, 'm4_catalog_reference_snapshot_invalid'); const signed = integrity(rawIntegrity, 'm4_catalog_reference_snapshot_invalid');
  const loaded = keyDocument(structuredClone(signingKeyDocument), 'm4_catalog_reference_snapshot_key_invalid');
  try {
    if (signed.keyId !== loaded.keyId) fail('m4_catalog_reference_snapshot_key_id_mismatch');
    const payloadDigest = sha(body); if (payloadDigest !== signed.payloadDigest) fail('m4_catalog_reference_snapshot_digest_mismatch');
    const expected = Buffer.from(signatureFor(CATALOG_DOMAIN, payloadDigest, loaded), 'base64url'); const received = Buffer.from(signed.signature, 'base64url');
    if (expected.length !== received.length || !crypto.timingSafeEqual(expected, received)) fail('m4_catalog_reference_snapshot_signature_mismatch');
    return structuredClone({ ...body, integrity: signed });
  } finally { loaded.key.fill(0); }
}

export async function collectM4SelectorScopeSnapshot(value) {
  if (!plain(value)) fail('m4_selector_scope_snapshot_input_invalid');
  const keys = ['snapshotId', 'revision', 'policy', 'observedAt', 'validThrough', 'selectorSource', 'keyDocument'];
  if (Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key))) fail('m4_selector_scope_snapshot_input_invalid');
  let policy; try { policy = structuredClone(value.policy); } catch { fail('m4_selector_scope_snapshot_input_invalid'); }
  if (!plain(policy) || policy.schema !== 'amf.content-protection-policy/v1' || typeof policy.revision !== 'string' || !REVISION.test(policy.revision)) fail('m4_selector_scope_snapshot_input_invalid');
  const selected = await collect(value.selectorSource, selector, 'm4_selector_scope_snapshot_input_invalid', MAX_SELECTORS);
  selected.sort((left, right) => compareText(left.sourceInstanceId, right.sourceInstanceId));
  const body = scopePayload({ schema: M4_SELECTOR_SCOPE_SNAPSHOT_SCHEMA, snapshotId: value.snapshotId, revision: value.revision,
    policyRevision: policy.revision, policyDigest: sha(policy), observedAt: value.observedAt, validThrough: value.validThrough,
    selectors: selected, selectorDigest: sha(selected) }, 'm4_selector_scope_snapshot_input_invalid');
  const loaded = keyDocument(value.keyDocument, 'm4_selector_scope_snapshot_key_invalid');
  try { const payloadDigest = sha(body); return structuredClone({ ...body, integrity: { algorithm: 'hmac-sha256', keyId: loaded.keyId,
    payloadDigest, signature: signatureFor(SCOPE_DOMAIN, payloadDigest, loaded) } }); } finally { loaded.key.fill(0); }
}

export function verifyM4SelectorScopeSnapshot(value, signingKeyDocument) {
  let item;
  try { item = snapshot(structuredClone(value), ['schema', 'snapshotId', 'revision', 'policyRevision', 'policyDigest', 'observedAt', 'validThrough', 'selectors', 'selectorDigest', 'integrity'], 'm4_selector_scope_snapshot_invalid'); }
  catch (error) { if (typeof error?.code === 'string' && error.code.startsWith('m4_')) throw error; fail('m4_selector_scope_snapshot_invalid'); }
  const { integrity: rawIntegrity, ...rawBody } = item;
  const body = scopePayload(rawBody, 'm4_selector_scope_snapshot_invalid'); const signed = integrity(rawIntegrity, 'm4_selector_scope_snapshot_invalid');
  const loaded = keyDocument(structuredClone(signingKeyDocument), 'm4_selector_scope_snapshot_key_invalid');
  try {
    if (signed.keyId !== loaded.keyId) fail('m4_selector_scope_snapshot_key_id_mismatch');
    const payloadDigest = sha(body); if (payloadDigest !== signed.payloadDigest) fail('m4_selector_scope_snapshot_digest_mismatch');
    const expected = Buffer.from(signatureFor(SCOPE_DOMAIN, payloadDigest, loaded), 'base64url'); const received = Buffer.from(signed.signature, 'base64url');
    if (expected.length !== received.length || !crypto.timingSafeEqual(expected, received)) fail('m4_selector_scope_snapshot_signature_mismatch');
    return structuredClone({ ...body, integrity: signed });
  } finally { loaded.key.fill(0); }
}

export function m4AuthorityEvidence(manifest) {
  const manifestId = manifest.snapshotId; const { payloadDigest: digest, signature } = manifest.integrity;
  return { manifestId, digest, signature };
}

export function m4PolicyDigest(policy) { return sha(policy); }
