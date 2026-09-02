import { normalizeSessionContextBinding, sessionBindingMatches, validateProjectionV2 } from './ingest/raw-projection-v2.mjs';
import { strictIsoTimestamp } from './ingest/transcripts/canonical.mjs';

export const RAW_PROJECTION_V2_PROOF_VERSION = 1;
export const DEFAULT_RAW_PROJECTION_V2_PAGE_SIZE = 128;

const EVIDENCE_KEYS = ['v1Count', 'v2Count', 'aliasCount', 'aliasOrphanCount', 'legacyFieldCount', 'literalScanCount'];

function validEvidence(evidence) {
  return evidence && EVIDENCE_KEYS.every(key => Number.isSafeInteger(evidence[key]) && evidence[key] >= 0)
    && evidence.aliasOrphanCount === 0 && evidence.legacyFieldCount === 0 && evidence.literalScanCount === 0;
}

function canonicalUtcTimestamp(value) {
  return Boolean(strictIsoTimestamp(value) && value.endsWith('Z') && new Date(value).toISOString() === value);
}

export function validateRawProjectionV2Proof(proof, revision) {
  return Boolean(proof
    && proof.version === RAW_PROJECTION_V2_PROOF_VERSION
    && Number.isSafeInteger(proof.mutationRevision)
    && proof.mutationRevision === revision
    && canonicalUtcTimestamp(proof.verifiedAt)
    && Number.isSafeInteger(proof.checkedEvents)
    && proof.checkedEvents >= 0
    && proof.checkedEvents === proof.evidence?.v2Count
    && validEvidence(proof.evidence));
}

export async function verifyAndPublishRawProjectionV2Proof(catalog, { pageSize = DEFAULT_RAW_PROJECTION_V2_PAGE_SIZE, now = () => new Date() } = {}) {
  if (!Number.isSafeInteger(pageSize) || pageSize < 1 || pageSize > 1024) throw new Error('raw_projection_v2_page_size_invalid');
  const startRevision = await catalog.rawV2ReadinessRevision();
  const evidence = await catalog.rawV2ReadinessEvidence();
  if (!validEvidence(evidence)) throw new Error('raw_projection_v2_invariant_failed');
  let after = null;
  let checkedEvents = 0;
  while (true) {
    const page = await catalog.listRawV2ReadinessPage({ after, limit: pageSize });
    if (!page || !Array.isArray(page.items) || (page.next !== null && typeof page.next !== 'string')) throw new Error('raw_projection_v2_page_invalid');
    for (const item of page.items) {
      validateProjectionV2(item.projection);
      normalizeSessionContextBinding(item.sessionBinding);
      if (!sessionBindingMatches(item.sessionBinding, item.projection)) throw new Error('raw_projection_v2_session_binding_invalid');
      checkedEvents += 1;
    }
    if (page.next === null) break;
    after = page.next;
  }
  if (checkedEvents !== evidence.v2Count) throw new Error('raw_projection_v2_count_changed');
  const proof = { version: RAW_PROJECTION_V2_PROOF_VERSION, mutationRevision: startRevision, verifiedAt: now().toISOString(), checkedEvents, evidence };
  const published = await catalog.publishRawV2ReadinessProof({ expectedRevision: startRevision, proof });
  if (!published) return { safe: false, reason: 'migration_proof_stale', evidence: { mutationRevision: startRevision, checkedEvents } };
  return { safe: true, reason: null, evidence: { persisted: true, ...proof } };
}
