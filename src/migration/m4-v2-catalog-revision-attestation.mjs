import crypto from 'node:crypto';

import { canonicalJson } from '../ingest/transcripts/canonical.mjs';
import { buildM4V2LogicalGroup } from './m4-v2-catalog-groups.mjs';

export const M4_V2_CATALOG_REVISION_ATTESTATION_SCHEMA = 'amf.m4-v2-catalog-revision-attestation/v1';

const DIGEST = /^sha256:[a-f0-9]{64}$/;
const LOGICAL_ID = /^lmsg_[a-f0-9]{64}$/;
const ID = /^[a-z][a-z0-9-]{2,79}$/;
const B64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const MAX_GROUPS = 2_000_000;
const MAX_OBSERVATIONS = 20_000_000;

function fail(code) { const error = new Error(code); error.code = code; throw error; }
function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function exact(value, keys) { return plain(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)); }
function clone(value, code) { try { return structuredClone(value); } catch { fail(code); } }
function digest(value) { return `sha256:${crypto.createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`; }
function signature(domain, payloadDigest, key) { return crypto.createHmac('sha256', key.key).update(canonicalJson([domain, payloadDigest, key.keyId]), 'utf8').digest('base64url'); }
function equal(left, right) { const a = Buffer.from(left, 'base64url'); const b = Buffer.from(right, 'base64url'); return a.length === b.length && crypto.timingSafeEqual(a, b); }

function signingKey(value, code) {
  const safe = clone(value, code);
  if (!exact(safe, ['schema', 'keyId', 'key']) || safe.schema !== 'amf.migration-signing-key/v1'
    || typeof safe.keyId !== 'string' || !ID.test(safe.keyId) || typeof safe.key !== 'string' || !B64.test(safe.key)) fail(code);
  const key = Buffer.from(safe.key, 'base64');
  if (key.length < 32 || key.length > 64 || key.toString('base64') !== safe.key) { key.fill(0); fail(code); }
  return { keyId: safe.keyId, key };
}

function traversal(value, code) {
  if (!exact(value, ['pageLimit', 'groupCount', 'observationCount', 'finalChain', 'catalogRevisionDigest'])
    || !Number.isSafeInteger(value.pageLimit) || value.pageLimit < 1 || value.pageLimit > 100
    || !Number.isSafeInteger(value.groupCount) || value.groupCount < 0 || value.groupCount > MAX_GROUPS
    || !Number.isSafeInteger(value.observationCount) || value.observationCount < 0 || value.observationCount > MAX_OBSERVATIONS
    || ![value.finalChain, value.catalogRevisionDigest].every(item => typeof item === 'string' && DIGEST.test(item))) fail(code);
  const safe = clone(value, code);
  if (safe.catalogRevisionDigest !== digest(['amf.m4-v2-catalog-revision-attestation/v1/revision', safe.groupCount, safe.observationCount, safe.finalChain])) fail(code);
  return safe;
}

function payload(value, code) {
  if (!exact(value, ['schema', 'traversal']) || value.schema !== M4_V2_CATALOG_REVISION_ATTESTATION_SCHEMA) fail(code);
  return { schema: value.schema, traversal: traversal(value.traversal, code) };
}

function document(value, code) {
  const safe = clone(value, code);
  if (!exact(safe, ['schema', 'traversal', 'integrity']) || !exact(safe.integrity, ['algorithm', 'keyId', 'payloadDigest', 'signature'])
    || safe.integrity.algorithm !== 'hmac-sha256' || typeof safe.integrity.keyId !== 'string' || !ID.test(safe.integrity.keyId)
    || typeof safe.integrity.payloadDigest !== 'string' || !DIGEST.test(safe.integrity.payloadDigest)
    || typeof safe.integrity.signature !== 'string' || !/^[A-Za-z0-9_-]{43,86}$/.test(safe.integrity.signature)) fail(code);
  return { ...payload({ schema: safe.schema, traversal: safe.traversal }, code), integrity: safe.integrity };
}

function dependencies(input) {
  if (!exact(input, ['catalog', 'keyDocument', 'pageLimit']) || !input.catalog || typeof input.catalog.listM4V2LogicalGroups !== 'function'
    || !Number.isSafeInteger(input.pageLimit) || input.pageLimit < 1 || input.pageLimit > 100) fail('m4_v2_catalog_attestation_input_invalid');
  return { list: input.catalog.listM4V2LogicalGroups.bind(input.catalog), key: signingKey(input.keyDocument, 'm4_v2_catalog_attestation_key_invalid'), pageLimit: input.pageLimit };
}

export async function attestM4V2CatalogRevision(input = {}) {
  const safe = dependencies(input);
  try {
    let after = null; let groups = 0; let observations = 0;
    let chain = digest(['amf.m4-v2-catalog-revision-attestation/v1/chain', 'initial']);
    while (true) {
      let page; try { page = await safe.list({ after, limit: safe.pageLimit }); } catch { fail('m4_v2_catalog_attestation_catalog_failed'); }
      if (!exact(page, ['items', 'next']) || !Array.isArray(page.items) || page.items.length > safe.pageLimit
        || !(page.next === null || (typeof page.next === 'string' && LOGICAL_ID.test(page.next)))) fail('m4_v2_catalog_attestation_catalog_invalid');
      let last = after;
      for (const candidate of page.items) {
        const logicalId = candidate?.logical?.logicalMessageId;
        if (!plain(candidate) || !plain(candidate.logical) || !Array.isArray(candidate.observations)
          || typeof logicalId !== 'string' || !LOGICAL_ID.test(logicalId) || (last !== null && logicalId <= last)) fail('m4_v2_catalog_attestation_catalog_invalid');
        last = logicalId;
      }
      if (page.next !== null && (page.items.length !== safe.pageLimit || page.next !== last)) fail('m4_v2_catalog_attestation_catalog_invalid');
      if (page.items.length === 0) break;
      for (const candidate of page.items) {
        let group; try { group = buildM4V2LogicalGroup(candidate.logical, candidate.observations); } catch { fail('m4_v2_catalog_attestation_catalog_invalid'); }
        groups += 1; observations += group.observations.length;
        if (groups > MAX_GROUPS || observations > MAX_OBSERVATIONS) fail('m4_v2_catalog_attestation_bounds_exceeded');
        const groupDigest = digest(group);
        chain = digest(['amf.m4-v2-catalog-revision-attestation/v1/chain', chain, group.logical.logicalMessageId, groupDigest]);
      }
      if (page.next === null) break;
      after = page.next;
    }
    const safePayload = payload({ schema: M4_V2_CATALOG_REVISION_ATTESTATION_SCHEMA,
      traversal: { pageLimit: safe.pageLimit, groupCount: groups, observationCount: observations,
        finalChain: chain, catalogRevisionDigest: digest(['amf.m4-v2-catalog-revision-attestation/v1/revision', groups, observations, chain]) } }, 'm4_v2_catalog_attestation_invalid');
    const payloadDigest = digest(safePayload);
    return { ...safePayload, integrity: { algorithm: 'hmac-sha256', keyId: safe.key.keyId, payloadDigest,
      signature: signature('amf.m4-v2-catalog-revision-attestation/v1/integrity', payloadDigest, safe.key) } };
  } finally { safe.key.key.fill(0); }
}

export function verifyM4V2CatalogRevisionAttestation(value, keyDocument) {
  const safe = document(value, 'm4_v2_catalog_attestation_invalid'); const key = signingKey(keyDocument, 'm4_v2_catalog_attestation_key_invalid');
  try {
    if (safe.integrity.keyId !== key.keyId) fail('m4_v2_catalog_attestation_key_mismatch');
    const { integrity, ...unsigned } = safe; const payloadDigest = digest(unsigned);
    if (payloadDigest !== integrity.payloadDigest) fail('m4_v2_catalog_attestation_digest_mismatch');
    if (!equal(integrity.signature, signature('amf.m4-v2-catalog-revision-attestation/v1/integrity', payloadDigest, key))) fail('m4_v2_catalog_attestation_signature_mismatch');
    return clone(safe, 'm4_v2_catalog_attestation_invalid');
  } finally { key.key.fill(0); }
}

export function canonicalM4V2CatalogRevisionAttestationDigest(value, keyDocument) {
  return digest(verifyM4V2CatalogRevisionAttestation(value, keyDocument));
}
