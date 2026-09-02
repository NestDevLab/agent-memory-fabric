import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { SqliteCatalog } from '../src/fabric-store.mjs';
import { validateRawProjectionV2Proof, verifyAndPublishRawProjectionV2Proof } from '../src/raw-projection-v2-readiness.mjs';

test('SQLite RAW v2 readiness is missing until a bounded verifier publishes a proof, then survives warm restart', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-raw-v2-proof-'));
  const databasePath = path.join(directory, 'catalog.sqlite');
  try {
    const catalog = new SqliteCatalog({ databasePath });
    assert.deepEqual(catalog.rawV2Readiness(), { safe: false, reason: 'production_postgres_required', evidence: { persisted: false, proofState: 'missing' } });
    const verified = await verifyAndPublishRawProjectionV2Proof(catalog, { now: () => new Date('2026-09-01T00:00:00.000Z') });
    assert.equal(verified.safe, true);
    assert.deepEqual({ safe: catalog.rawV2Readiness().safe, reason: catalog.rawV2Readiness().reason, proofState: catalog.rawV2Readiness().evidence.proofState }, { safe: false, reason: 'production_postgres_required', proofState: 'valid' });
    catalog.close();
    const warm = new SqliteCatalog({ databasePath });
    assert.equal(warm.rawV2Readiness().evidence.proofState, 'valid');
    warm.db.prepare('UPDATE raw_projection_v2_readiness_v2 SET mutation_revision=mutation_revision+1 WHERE singleton=1').run();
    assert.equal(warm.rawV2Readiness().evidence.proofState, 'stale');
    assert.equal((await verifyAndPublishRawProjectionV2Proof(warm)).safe, true, 'a bounded re-verification recovers stale proof state');
    assert.equal(warm.rawV2Readiness().evidence.proofState, 'valid');
    warm.close();
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test('persisted proof validation rejects forged checked-event counts and non-canonical timestamps', () => {
  const evidence = { v1Count: 0, v2Count: 0, aliasCount: 0, aliasOrphanCount: 0, legacyFieldCount: 0, literalScanCount: 0 };
  const proof = { version: 1, mutationRevision: 0, verifiedAt: '2026-09-01T00:00:00.000Z', checkedEvents: 0, evidence };
  assert.equal(validateRawProjectionV2Proof(proof, 0), true);
  assert.equal(validateRawProjectionV2Proof({ ...proof, checkedEvents: 1 }, 0), false);
  assert.equal(validateRawProjectionV2Proof({ ...proof, verifiedAt: '2026-09-01T00:00:00+00:00' }, 0), false);

  const catalog = new SqliteCatalog({ databasePath: ':memory:' });
  try {
    assert.equal(catalog.publishRawV2ReadinessProof({ expectedRevision: 0, proof: { ...proof, checkedEvents: 1 } }), true);
    assert.equal(catalog.rawV2Readiness().evidence.proofState, 'stale');
  } finally { catalog.close(); }
});

test('bounded verifier fails closed on invalid pages and CAS publication races', async () => {
  let published = false;
  const projection = JSON.parse(fs.readFileSync(new URL('./fixtures/raw-projection-v2.conformance.json', import.meta.url), 'utf8'));
  let proof;
  const valid = {
    async rawV2ReadinessRevision() { return 2; },
    async rawV2ReadinessEvidence() { return { v1Count: 3, v2Count: 1, aliasCount: 2, aliasOrphanCount: 0, legacyFieldCount: 0, literalScanCount: 0 }; },
    async listRawV2ReadinessPage() { return { items: [{ projection, sessionBinding: { conversation: projection.contextTags.conversation, room: projection.contextTags.room } }], next: null }; },
    async publishRawV2ReadinessProof(input) { proof = input.proof; return true; }
  };
  assert.equal((await verifyAndPublishRawProjectionV2Proof(valid)).safe, true);
  assert.deepEqual(proof.evidence, { v1Count: 3, v2Count: 1, aliasCount: 2, aliasOrphanCount: 0, legacyFieldCount: 0, literalScanCount: 0 });
  assert.equal(proof.checkedEvents, 1);

  const stale = {
    async rawV2ReadinessRevision() { return 4; },
    async rawV2ReadinessEvidence() { return { v1Count: 0, v2Count: 0, aliasCount: 0, aliasOrphanCount: 0, legacyFieldCount: 0, literalScanCount: 0 }; },
    async listRawV2ReadinessPage() { return { items: [], next: null }; },
    async publishRawV2ReadinessProof() { return false; }
  };
  const result = await verifyAndPublishRawProjectionV2Proof(stale);
  assert.deepEqual(result, { safe: false, reason: 'migration_proof_stale', evidence: { mutationRevision: 4, checkedEvents: 0 } });
  const invalid = {
    async rawV2ReadinessRevision() { return 1; },
    async rawV2ReadinessEvidence() { return { v1Count: 0, v2Count: 1, aliasCount: 0, aliasOrphanCount: 0, legacyFieldCount: 0, literalScanCount: 0 }; },
    async listRawV2ReadinessPage() { return { items: [{ projection: {}, sessionBinding: {} }], next: null }; },
    async publishRawV2ReadinessProof() { published = true; return true; }
  };
  await assert.rejects(verifyAndPublishRawProjectionV2Proof(invalid));
  assert.equal(published, false);

  const mismatchedBinding = {
    async rawV2ReadinessRevision() { return 1; },
    async rawV2ReadinessEvidence() { return { v1Count: 0, v2Count: 1, aliasCount: 0, aliasOrphanCount: 0, legacyFieldCount: 0, literalScanCount: 0 }; },
    async listRawV2ReadinessPage() { return { items: [{ projection, sessionBinding: { conversation: ['hmac-sha256:routing-v1:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'], room: projection.contextTags.room } }], next: null }; },
    async publishRawV2ReadinessProof() { throw new Error('must_not_publish_invalid_session_binding'); }
  };
  await assert.rejects(verifyAndPublishRawProjectionV2Proof(mismatchedBinding), /raw_projection_v2_session_binding_invalid/);

  const failedInvariant = {
    async rawV2ReadinessRevision() { return 1; },
    async rawV2ReadinessEvidence() { return { v1Count: 1, v2Count: 0, aliasCount: 1, aliasOrphanCount: 1, legacyFieldCount: 0, literalScanCount: 0 }; },
    async listRawV2ReadinessPage() { throw new Error('must_not_scan_after_failed_invariant'); },
    async publishRawV2ReadinessProof() { throw new Error('must_not_publish_after_failed_invariant'); }
  };
  await assert.rejects(verifyAndPublishRawProjectionV2Proof(failedInvariant), /raw_projection_v2_invariant_failed/);
});
