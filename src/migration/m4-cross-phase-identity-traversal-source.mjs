import crypto from 'node:crypto';

import { canonicalJson } from '../ingest/transcripts/canonical.mjs';
import { RAW_EVENT_HTTP_MAX_BODY_BYTES, normalizeIngestKeyRing } from '../ingest/raw-event-contract.mjs';
import { createM4V2CatalogRevisionAccumulator, verifyM4V2CatalogRevisionAttestation } from './m4-v2-catalog-revision-attestation.mjs';
import { buildM4V2LogicalGroup } from './m4-v2-catalog-groups.mjs';
import { isPotentialM4ConversationProjection } from './m4-v2-conversation-eligibility.mjs';
import { readM4V2CatalogObservation, readM4V2Observation } from './m4-v2-observation-reader.mjs';
import { projectM4V2LogicalGroup } from './m4-v2-conversation-projector.mjs';
import { createM4CrossPhaseIdentityTraversalGroupCheckpoint } from './m4-cross-phase-identity-traversal-store.mjs';

const DIGEST = /^sha256:[a-f0-9]{64}$/;
const ID = /^[a-z][a-z0-9-]{2,79}$/;
const LOGICAL_ID = /^lmsg_[a-f0-9]{64}$/;
const EXCLUSION_REASONS = new Set(['preferred_ineligible', 'no_eligible_observations', 'deletion_without_history']);

function fail(code) { const error = new Error(code); error.code = code; throw error; }
function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function object(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function exact(value, keys) { return plain(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)); }
function clone(value, code) { try { return structuredClone(value); } catch { fail(code); } }
function digest(value) { return `sha256:${crypto.createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`; }

function dependencies(value) {
  const allowed = ['catalog', 'rawStore', 'ingestKeys', 'verifyCatalogBinding', 'auditDecrypt', 'integrityFor', 'catalogBaseline', 'catalogKeyDocument', 'runId', 'planDigest', 'pageLimit', 'maxCiphertextBytes'];
  if (!plain(value) || Object.keys(value).some(key => !allowed.includes(key))) fail('m4_cross_phase_identity_traversal_source_dependency_invalid');
  value = Object.fromEntries(allowed.map(key => [key, value[key]]));
  const catalog = value.catalog; const rawStore = value.rawStore;
  const listGroups = catalog?.listM4V2LogicalGroups; const getCiphertext = rawStore?.getClientCiphertext;
  if (!object(catalog) || !object(rawStore) || typeof listGroups !== 'function'
    || typeof getCiphertext !== 'function' || typeof value.verifyCatalogBinding !== 'function'
    || typeof value.auditDecrypt !== 'function' || typeof value.integrityFor !== 'function'
    || typeof value.runId !== 'string' || !ID.test(value.runId)
    || typeof value.planDigest !== 'string' || !DIGEST.test(value.planDigest)) {
    fail('m4_cross_phase_identity_traversal_source_dependency_invalid');
  }
  const pageLimit = value.pageLimit ?? 50;
  const maxCiphertextBytes = value.maxCiphertextBytes ?? RAW_EVENT_HTTP_MAX_BODY_BYTES;
  if (!Number.isSafeInteger(pageLimit) || pageLimit < 1 || pageLimit > 100
    || !Number.isSafeInteger(maxCiphertextBytes) || maxCiphertextBytes < 1024 || maxCiphertextBytes > RAW_EVENT_HTTP_MAX_BODY_BYTES) {
    fail('m4_cross_phase_identity_traversal_source_dependency_invalid');
  }
  let ingestKeys; let baseline;
  try {
    normalizeIngestKeyRing(value.ingestKeys); ingestKeys = structuredClone(value.ingestKeys);
    baseline = verifyM4V2CatalogRevisionAttestation(value.catalogBaseline, value.catalogKeyDocument);
  } catch { fail('m4_cross_phase_identity_traversal_source_dependency_invalid'); }
  if (baseline.schema !== 'amf.m4-v2-catalog-revision-attestation/v2'
    || baseline.traversal.groupCount < 1 || baseline.traversal.coveredThrough === null) {
    fail('m4_cross_phase_identity_traversal_source_empty_catalog');
  }
  return Object.freeze({
    listGroups: listGroups.bind(catalog),
    getCiphertext: getCiphertext.bind(rawStore),
    ingestKeys, verifyCatalogBinding: value.verifyCatalogBinding,
    auditDecrypt: value.auditDecrypt, integrityFor: value.integrityFor,
    runId: value.runId, planDigest: value.planDigest, baseline,
    baselineDigest: digest(baseline), pageLimit, maxCiphertextBytes,
  });
}

function openRequest(value) {
  if (!exact(value, ['afterSequence', 'afterCheckpoint'])
    || !Number.isSafeInteger(value.afterSequence) || value.afterSequence < 0 || value.afterSequence > 2_000_000
    || !((value.afterSequence === 0 && value.afterCheckpoint === null)
      || (value.afterSequence > 0 && exact(value.afterCheckpoint, ['id', 'digest'])
        && typeof value.afterCheckpoint.id === 'string' && ID.test(value.afterCheckpoint.id)
        && typeof value.afterCheckpoint.digest === 'string' && DIGEST.test(value.afterCheckpoint.digest)))) {
    fail('m4_cross_phase_identity_traversal_source_request_invalid');
  }
  return clone(value, 'm4_cross_phase_identity_traversal_source_request_invalid');
}

export function canonicalizeM4CrossPhaseIdentityTraversalBlock(value) {
  const safe = clone(value, 'm4_cross_phase_identity_traversal_source_project_failed');
  if (!plain(safe) || !Array.isArray(safe.events)) fail('m4_cross_phase_identity_traversal_source_project_failed');
  safe.events.sort((left, right) => left.legacyEventId.localeCompare(right.legacyEventId));
  return safe;
}

function canonicalizeIdentityBlockGroup(identityBlocks) {
  if (!Array.isArray(identityBlocks) || identityBlocks.length < 1 || identityBlocks.length > 8_192) {
    fail('m4_cross_phase_identity_traversal_source_project_failed');
  }
  const blocks = identityBlocks.map(canonicalizeM4CrossPhaseIdentityTraversalBlock)
    .sort((left, right) => left.session?.legacySessionId?.localeCompare(right.session?.legacySessionId) || digest(left).localeCompare(digest(right)));
  if (blocks.length === 1) return blocks[0];
  if (blocks.some((item, index) => index > 0
    && item.session?.legacySessionId === blocks[index - 1].session?.legacySessionId)) {
    fail('m4_cross_phase_identity_traversal_source_project_failed');
  }
  return {
    schema: 'amf.m4-cross-phase-projector-identity-block-batch/v1',
    blocks,
  };
}

function groupResult({ sequence, logicalMessageId, projected, identityBlocks }) {
  if (projected.outcome === 'projected') {
    const canonicalIdentityBlock = canonicalizeIdentityBlockGroup(identityBlocks);
    const identityBlockDigest = digest(canonicalIdentityBlock);
    const checkpoint = createM4CrossPhaseIdentityTraversalGroupCheckpoint({ sequence, logicalMessageId, outcome: 'accepted', identityBlockDigest });
    return Object.freeze({ sequence, checkpoint, logicalMessageId, outcome: 'accepted', reason: null, identityBlock: canonicalIdentityBlock, identityBlockDigest });
  }
  if (projected.outcome !== 'excluded' || !EXCLUSION_REASONS.has(projected.reason) || identityBlocks.length !== 0) {
    fail('m4_cross_phase_identity_traversal_source_project_failed');
  }
  const checkpoint = createM4CrossPhaseIdentityTraversalGroupCheckpoint({ sequence, logicalMessageId, outcome: 'excluded', identityBlockDigest: null });
  return Object.freeze({ sequence, checkpoint, logicalMessageId, outcome: 'excluded', reason: projected.reason, identityBlock: null, identityBlockDigest: null });
}

// This source has exactly one public payload: a content-free identity block.
// It enumerates every signed-catalog group, including exclusions, so a runner
// can advance its durable checkpoint once per logical group rather than per
// projected event.
export function createM4CrossPhaseIdentityTraversalSource(input = {}) {
  const safe = dependencies(input);
  return Object.freeze({
    binding: Object.freeze({ runId: safe.runId, planDigest: safe.planDigest, catalogBaselineDigest: safe.baselineDigest, groupCount: safe.baseline.traversal.groupCount }),
    open(requestInput) {
      const request = openRequest(requestInput);
      return (async function* enumerate() {
        let after = null; let sequence = 0; let emitted = 0; let resumeVerified = request.afterSequence === 0; const attestation=createM4V2CatalogRevisionAccumulator();
        try {
          while (true) {
            let page;
            try { page = await safe.listGroups({ after, limit: safe.pageLimit }); }
            catch { fail('m4_cross_phase_identity_traversal_source_catalog_failed'); }
            if (!exact(page, ['items', 'next']) || !Array.isArray(page.items) || page.items.length > safe.pageLimit
              || !(page.next === null || (typeof page.next === 'string' && LOGICAL_ID.test(page.next)))) {
              fail('m4_cross_phase_identity_traversal_source_catalog_failed');
            }
            let pageLast = after;
            for (const candidate of page.items) {
              const logicalId = candidate?.logical?.logicalMessageId;
              if (!plain(candidate) || !plain(candidate.logical) || !Array.isArray(candidate.observations)
                || typeof logicalId !== 'string' || !LOGICAL_ID.test(logicalId)
                || (pageLast !== null && logicalId <= pageLast)) fail('m4_cross_phase_identity_traversal_source_catalog_failed');
              pageLast = logicalId;
            }
            if (page.next !== null && (page.items.length !== safe.pageLimit || page.next !== pageLast)) fail('m4_cross_phase_identity_traversal_source_catalog_failed');
            if (page.items.length === 0) break;
            for (const candidate of page.items) {
              let group;
              try { group = buildM4V2LogicalGroup(candidate.logical, candidate.observations); }
              catch { fail('m4_cross_phase_identity_traversal_source_catalog_failed'); }
              if (sequence >= safe.baseline.traversal.groupCount) fail('m4_cross_phase_identity_traversal_source_drift');
              try { attestation.append(group); } catch { fail('m4_cross_phase_identity_traversal_source_catalog_failed'); }
              const observations = [];
              for (const [index, catalogRow] of group.observations.entries()) {
                if (!isPotentialM4ConversationProjection(catalogRow.projection)) {
                  try {
                    observations.push(readM4V2CatalogObservation({
                      catalogRow,
                      migrationSequence: index + 1,
                    }));
                  } catch { fail('m4_cross_phase_identity_traversal_source_read_failed'); }
                  continue;
                }
                let envelope;
                try { envelope = await safe.getCiphertext(catalogRow.contentId); }
                catch { fail('m4_cross_phase_identity_traversal_source_envelope_unavailable'); }
                try {
                  observations.push(await readM4V2Observation({ catalogRow, envelope, ingestKeys: safe.ingestKeys,
                    migrationSequence: index + 1, verifyCatalogBinding: safe.verifyCatalogBinding,
                    auditDecrypt: safe.auditDecrypt, maxCiphertextBytes: safe.maxCiphertextBytes }));
                } catch { fail('m4_cross_phase_identity_traversal_source_read_failed'); }
              }
              const identityBlocks = []; let projected;
              try {
                projected = await projectM4V2LogicalGroup({ logical: group.logical, observations, integrityFor: safe.integrityFor,
                  identityCollector: { async accept(block) { identityBlocks.push(clone(block, 'm4_cross_phase_identity_traversal_source_project_failed')); } } });
              } catch { fail('m4_cross_phase_identity_traversal_source_project_failed'); }
              if (!exact(projected, ['schema', 'outcome', 'reason', 'evidence', 'events'])
                || identityBlocks.length > group.observations.length) fail('m4_cross_phase_identity_traversal_source_project_failed');
              sequence += 1;
              const result = groupResult({ sequence, logicalMessageId: group.logical.logicalMessageId, projected, identityBlocks });
              if (sequence <= request.afterSequence) {
                if (sequence === request.afterSequence && canonicalJson(result.checkpoint) === canonicalJson(request.afterCheckpoint)) resumeVerified = true;
                continue;
              }
              if (!resumeVerified) fail('m4_cross_phase_identity_traversal_source_drift');
              yield result;
              emitted += 1;
            }
            after = page.next;
            if (after === null) break;
          }
          let traversal;
          try { traversal=attestation.traversal(safe.baseline.traversal.pageLimit); } catch { fail('m4_cross_phase_identity_traversal_source_catalog_failed'); }
          if (sequence !== safe.baseline.traversal.groupCount || canonicalJson(traversal)!==canonicalJson(safe.baseline.traversal) || !resumeVerified) fail('m4_cross_phase_identity_traversal_source_drift');
          if (emitted > safe.baseline.traversal.groupCount - request.afterSequence) fail('m4_cross_phase_identity_traversal_source_drift');
        } catch (error) {
          if (typeof error?.code === 'string' && error.code.startsWith('m4_cross_phase_identity_traversal_source_')) throw error;
          fail('m4_cross_phase_identity_traversal_source_enumeration_failed');
        }
      })();
    },
  });
}
