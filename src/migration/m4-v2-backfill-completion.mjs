import crypto from 'node:crypto';

import { canonicalJson } from '../ingest/transcripts/canonical.mjs';
import { verifyM4BackfillGate } from './m4-backfill-gate.mjs';
import { planM4V2Backfill } from './m4-v2-backfill-runner.mjs';
import { verifyM4V2CatalogRevisionAttestation } from './m4-v2-catalog-revision-attestation.mjs';

export const M4_V2_ARCHIVE_BACKFILL_COMPLETION_SCHEMA = 'amf.m4-v2-archive-backfill-completion/v1';

const DIGEST = /^sha256:[a-f0-9]{64}$/;
const ID = /^[a-z][a-z0-9-]{2,79}$/;
const B64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

function fail(code) { const error = new Error(code); error.code = code; throw error; }
function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function exact(value, keys) { return plain(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)); }
function clone(value, code) { try { return structuredClone(value); } catch { fail(code); } }
function digest(value) { return `sha256:${crypto.createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`; }
function equal(left, right) { const a = Buffer.from(left, 'base64url'); const b = Buffer.from(right, 'base64url'); return a.length === b.length && crypto.timingSafeEqual(a, b); }
function signature(domain, payloadDigest, key) { return crypto.createHmac('sha256', key.key).update(canonicalJson([domain, payloadDigest, key.keyId]), 'utf8').digest('base64url'); }

function signingKey(value, code) {
  const safe = clone(value, code);
  if (!exact(safe, ['schema', 'keyId', 'key']) || safe.schema !== 'amf.migration-signing-key/v1'
    || typeof safe.keyId !== 'string' || !ID.test(safe.keyId) || typeof safe.key !== 'string' || !B64.test(safe.key)) fail(code);
  const key = Buffer.from(safe.key, 'base64');
  if (key.length < 32 || key.length > 64 || key.toString('base64') !== safe.key) { key.fill(0); fail(code); }
  return { keyId: safe.keyId, key };
}
function checkpoint(value, code) {
  if (!exact(value, ['id', 'digest']) || typeof value.id !== 'string' || !ID.test(value.id)
    || typeof value.digest !== 'string' || !DIGEST.test(value.digest)) fail(code);
  return { id: value.id, digest: value.digest };
}
function runnerResult(value, code) {
  if (!exact(value, ['schema', 'runId', 'phase', 'processed', 'duplicates', 'lastCheckpoint', 'complete'])
    || value.schema !== 'amf.m4-backfill-result/v1' || typeof value.runId !== 'string' || !ID.test(value.runId)
    || value.phase !== 'v2-archive' || !Number.isSafeInteger(value.processed) || value.processed < 0
    || !Number.isSafeInteger(value.duplicates) || value.duplicates < 0 || value.duplicates > value.processed
    || value.complete !== true) fail(code);
  return { schema: value.schema, runId: value.runId, phase: value.phase, processed: value.processed,
    duplicates: value.duplicates, lastCheckpoint: checkpoint(value.lastCheckpoint, code), complete: true };
}
function payload(value, code) {
  const keys = ['schema', 'state', 'manifestId', 'revision', 'gateDigest', 'runnerPlanDigest',
    'catalogAttestationDigest', 'finalCheckpoint', 'resultDigest', 'catalogAttestationKeyId', 'completionKeyId'];
  if (!exact(value, keys) || value.schema !== M4_V2_ARCHIVE_BACKFILL_COMPLETION_SCHEMA || value.state !== 'complete'
    || typeof value.manifestId !== 'string' || !ID.test(value.manifestId) || !Number.isSafeInteger(value.revision) || value.revision < 1
    || ![value.gateDigest, value.runnerPlanDigest, value.catalogAttestationDigest, value.resultDigest].every(item => typeof item === 'string' && DIGEST.test(item))
    || typeof value.catalogAttestationKeyId !== 'string' || !ID.test(value.catalogAttestationKeyId)
    || typeof value.completionKeyId !== 'string' || !ID.test(value.completionKeyId)) fail(code);
  return { schema: value.schema, state: 'complete', manifestId: value.manifestId, revision: value.revision,
    gateDigest: value.gateDigest, runnerPlanDigest: value.runnerPlanDigest,
    catalogAttestationDigest: value.catalogAttestationDigest, finalCheckpoint: checkpoint(value.finalCheckpoint, code),
    resultDigest: value.resultDigest, catalogAttestationKeyId: value.catalogAttestationKeyId, completionKeyId: value.completionKeyId };
}
function document(value, code) {
  const safe = clone(value, code);
  if (!exact(safe, ['schema', 'state', 'manifestId', 'revision', 'gateDigest', 'runnerPlanDigest',
    'catalogAttestationDigest', 'finalCheckpoint', 'resultDigest', 'catalogAttestationKeyId', 'completionKeyId', 'integrity'])
    || !exact(safe.integrity, ['algorithm', 'keyId', 'payloadDigest', 'signature']) || safe.integrity.algorithm !== 'hmac-sha256'
    || typeof safe.integrity.keyId !== 'string' || !ID.test(safe.integrity.keyId)
    || typeof safe.integrity.payloadDigest !== 'string' || !DIGEST.test(safe.integrity.payloadDigest)
    || typeof safe.integrity.signature !== 'string' || !/^[A-Za-z0-9_-]{43,86}$/.test(safe.integrity.signature)) fail(code);
  const { integrity, ...unsigned } = safe;
  return { ...payload(unsigned, code), integrity };
}

export async function createM4V2ArchiveBackfillCompletion(input = {}) {
  const keys = ['manifestId', 'revision', 'gateInput', 'runnerPlan', 'result', 'preCatalogAttestation',
    'postCatalogAttestation', 'catalogAttestationKeyDocument', 'completionKeyDocument'];
  if (!exact(input, keys)) fail('m4_v2_archive_completion_input_invalid');
  const catalogKeyDocument = clone(input.catalogAttestationKeyDocument, 'm4_v2_archive_completion_catalog_key_invalid');
  let catalogKey; let completionKey;
  try {
    catalogKey = signingKey(catalogKeyDocument, 'm4_v2_archive_completion_catalog_key_invalid');
    const completionKeyDocument = clone(input.completionKeyDocument, 'm4_v2_archive_completion_key_invalid');
    completionKey = signingKey(completionKeyDocument, 'm4_v2_archive_completion_key_invalid');
    const catalogBlock = Buffer.alloc(64); const completionBlock = Buffer.alloc(64);
    try {
      catalogKey.key.copy(catalogBlock); completionKey.key.copy(completionBlock);
      if (catalogKey.keyId === completionKey.keyId || crypto.timingSafeEqual(catalogBlock, completionBlock)) fail('m4_v2_archive_completion_key_separation_invalid');
    } finally { catalogBlock.fill(0); completionBlock.fill(0); }
    let gate; let planned; try { gate = verifyM4BackfillGate(clone(input.gateInput, 'm4_v2_archive_completion_gate_invalid')); planned = await planM4V2Backfill({ gateInput: input.gateInput, maxEvents: input.runnerPlan?.maxEvents }); }
    catch { fail('m4_v2_archive_completion_gate_or_plan_invalid'); }
    if (gate.phase !== 'v2-archive' || canonicalJson(planned) !== canonicalJson(input.runnerPlan)) fail('m4_v2_archive_completion_plan_mismatch');
    const result = runnerResult(clone(input.result, 'm4_v2_archive_completion_result_invalid'), 'm4_v2_archive_completion_result_invalid');
    if (result.runId !== planned.runId || result.phase !== planned.phase) fail('m4_v2_archive_completion_result_mismatch');
    const before = verifyM4V2CatalogRevisionAttestation(input.preCatalogAttestation, catalogKeyDocument);
    const after = verifyM4V2CatalogRevisionAttestation(input.postCatalogAttestation, catalogKeyDocument);
    if (before.schema !== 'amf.m4-v2-catalog-revision-attestation/v2' || after.schema !== 'amf.m4-v2-catalog-revision-attestation/v2') fail('m4_v2_archive_completion_catalog_schema_invalid');
    const catalogAttestationDigest = digest(before);
    if (catalogAttestationDigest !== digest(after)) fail('m4_v2_archive_completion_catalog_changed');
    const unsigned = payload({ schema: M4_V2_ARCHIVE_BACKFILL_COMPLETION_SCHEMA, state: 'complete', manifestId: input.manifestId,
      revision: input.revision, gateDigest: digest(gate), runnerPlanDigest: planned.planDigest,
      catalogAttestationDigest, finalCheckpoint: result.lastCheckpoint, resultDigest: digest(result),
      catalogAttestationKeyId: catalogKey.keyId, completionKeyId: completionKey.keyId }, 'm4_v2_archive_completion_input_invalid');
    const payloadDigest = digest(unsigned);
    return { ...unsigned, integrity: { algorithm: 'hmac-sha256', keyId: completionKey.keyId, payloadDigest,
      signature: signature('amf.m4-v2-archive-backfill-completion/v1/integrity', payloadDigest, completionKey) } };
  } finally { catalogKey?.key.fill(0); completionKey?.key.fill(0); }
}

export function verifyM4V2ArchiveBackfillCompletion(value, completionKeyDocument) {
  const safe = document(value, 'm4_v2_archive_completion_invalid'); const key = signingKey(completionKeyDocument, 'm4_v2_archive_completion_key_invalid');
  try {
    if (safe.completionKeyId !== key.keyId || safe.integrity.keyId !== key.keyId) fail('m4_v2_archive_completion_key_mismatch');
    const { integrity, ...unsigned } = safe; const payloadDigest = digest(unsigned);
    if (payloadDigest !== integrity.payloadDigest) fail('m4_v2_archive_completion_digest_mismatch');
    if (!equal(integrity.signature, signature('amf.m4-v2-archive-backfill-completion/v1/integrity', payloadDigest, key))) fail('m4_v2_archive_completion_signature_mismatch');
    return clone(safe, 'm4_v2_archive_completion_invalid');
  } finally { key.key.fill(0); }
}

export function deriveM4V2ArchiveRegistryBinding(completion, completionKeyDocument, catalogAttestation, catalogAttestationKeyDocument) {
  const safeCatalogKeyDocument = clone(catalogAttestationKeyDocument, 'm4_v2_archive_completion_catalog_key_invalid');
  const safeCompletionKeyDocument = clone(completionKeyDocument, 'm4_v2_archive_completion_key_invalid');
  let catalogKey; let completionKey;
  try {
    catalogKey = signingKey(safeCatalogKeyDocument, 'm4_v2_archive_completion_catalog_key_invalid');
    completionKey = signingKey(safeCompletionKeyDocument, 'm4_v2_archive_completion_key_invalid');
    const safeCompletion = verifyM4V2ArchiveBackfillCompletion(completion, safeCompletionKeyDocument);
    const safeCatalog = verifyM4V2CatalogRevisionAttestation(catalogAttestation, safeCatalogKeyDocument);
    const catalogBlock = Buffer.alloc(64); const completionBlock = Buffer.alloc(64);
    try {
      catalogKey.key.copy(catalogBlock); completionKey.key.copy(completionBlock);
      if (catalogKey.keyId === completionKey.keyId || crypto.timingSafeEqual(catalogBlock, completionBlock)) fail('m4_v2_archive_completion_key_separation_invalid');
    } finally { catalogBlock.fill(0); completionBlock.fill(0); }
    if (safeCatalog.schema !== 'amf.m4-v2-catalog-revision-attestation/v2'
      || safeCompletion.catalogAttestationKeyId !== safeCatalog.integrity.keyId
      || safeCompletion.catalogAttestationKeyId !== catalogKey.keyId
      || safeCompletion.catalogAttestationDigest !== digest(safeCatalog)) fail('m4_v2_archive_completion_catalog_binding_mismatch');
    return { completionDigest: digest(safeCompletion), catalogRevisionDigest: safeCatalog.traversal.catalogRevisionDigest };
  } finally { catalogKey?.key.fill(0); completionKey?.key.fill(0); }
}
